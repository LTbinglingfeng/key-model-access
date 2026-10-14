package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestRPCNegotiationPreservesV2Policies(t *testing.T) {
	for _, host := range []uint32{1, 2, 3, 5, 6, 7} {
		t.Run(fmt.Sprint(host), func(t *testing.T) {
			globalState.clear()
			t.Cleanup(globalState.clear)
			request, err := json.Marshal(lifecycleRequest{SchemaVersion: host, ConfigYAML: []byte("version: 2\npolicies:\n  - caller_scope: " + scopeA + "\n    allow_models: ['vendor/a&b']\n")})
			if err != nil {
				t.Fatal(err)
			}
			raw, err := handleMethod(methodPluginRegister, request)
			if err != nil {
				t.Fatal(err)
			}
			var registration registration
			unwrapEnvelope(t, raw, &registration)
			wantSchema := host
			if wantSchema > rpcSchemaVersion {
				wantSchema = rpcSchemaVersion
			}
			if registration.SchemaVersion != wantSchema {
				t.Fatalf("RPC schema = %d, want %d", registration.SchemaVersion, wantSchema)
			}
			supported := host >= minimumRPCSchemaVersion
			if registration.Capabilities.RequestInterceptor != supported {
				t.Fatal("incorrect interceptor capability")
			}
			cfg, snapshot, _, _, _, _ := globalState.current()
			if cfg.Version != 2 {
				t.Fatalf("policy version = %d", cfg.Version)
			}
			if snapshot.BlockAll == supported {
				t.Fatalf("unexpected fail-closed state: %v", snapshot.BlockAll)
			}
			if !supported {
				return
			}
			if !policyAllows(snapshot.ByCallerScope[scopeA], "vendor/a&b") {
				t.Fatal("v2 policy was not retained")
			}
			for model, denied := range map[string]bool{"vendor/a&b": false, "other": true} {
				payload, _ := json.Marshal(requestInterceptRequest{RequestedModel: model, Metadata: map[string]any{"caller_scope": scopeA}})
				for _, method := range []string{methodRequestInterceptBefore, methodRequestInterceptAfter} {
					result, err := handleMethod(method, payload)
					if err != nil {
						t.Fatal(err)
					}
					var response requestInterceptResponse
					unwrapEnvelope(t, result, &response)
					if response.Terminate != denied || (denied && response.StatusCode != http.StatusForbidden) {
						t.Fatalf("%s model %q: %#v", method, model, response)
					}
				}
			}
		})
	}
}

func TestRawManagementPolicyRoundTrip(t *testing.T) {
	model := `vendor/a&b<test>"'`
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{CallerScope: scopeA, AllowModels: []string{model}}}})
	raw, err := managementPolicies()
	if err != nil {
		t.Fatal(err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	var payload struct {
		Policy policyDocument `json:"policy"`
	}
	if err := json.Unmarshal(response.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Policy.Version != 2 || payload.Policy.Policies[0].AllowModels[0] != model {
		t.Fatalf("policy changed: %#v", payload.Policy)
	}
	body, _ := json.Marshal(payload.Policy)
	updated, err := managementReplacePolicies(body, etagForRevision(globalState.policyRevision()))
	if err != nil {
		t.Fatal(err)
	}
	unwrapEnvelope(t, updated, &response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("save failed: %s", response.Body)
	}
	_, snapshot, _, _, _, _ := globalState.current()
	if !policyAllows(snapshot.ByCallerScope[scopeA], model) {
		t.Fatal("round trip changed policy")
	}
}
