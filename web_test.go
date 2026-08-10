package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestManagementRegistrationIncludesSettingsResource(t *testing.T) {
	registration := managementRegistration()
	if len(registration.Resources) != 1 {
		t.Fatalf("resources = %#v", registration.Resources)
	}
	resource := registration.Resources[0]
	if resource.Path != "/settings" || resource.Menu == "" {
		t.Fatalf("settings resource = %#v", resource)
	}
	foundInitializer := false
	for _, route := range registration.Routes {
		if route.Method == http.MethodPost && route.Path == initializeStoragePath {
			foundInitializer = true
			break
		}
	}
	if !foundInitializer {
		t.Fatalf("management routes missing default storage initializer: %#v", registration.Routes)
	}
}

func TestSettingsPageEmbedsAssetsWithNonceCSP(t *testing.T) {
	raw, err := settingsPage()
	if err != nil {
		t.Fatalf("settingsPage() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
	body := string(response.Body)
	for _, marker := range []string{"{{NONCE}}", "{{CSS}}", "{{JS}}"} {
		if strings.Contains(body, marker) {
			t.Fatalf("settings page retains template marker %s", marker)
		}
	}
	for _, expected := range []string{
		"id=\"authGate\"",
		"id=\"policyNav\"",
		"class=\"commandbar\"",
		"is-embedded",
		"const PATHS",
		"/v0/management/api-keys",
		"/v0/management/api-key-aliases",
		"/v1/models",
		"/initialize-storage",
		"/v0/management/plugins/key-model-access/config",
		"plugins_dir",
		"cli-proxy-auth",
		"cli-proxy-theme",
		"class=\"model-trigger",
		"<progress class=\"selection-meter\"",
		"state.pendingDraft = serializablePolicy()",
		"const commonWildcards",
		"cli-proxy-api:caller-scope:v1\\0",
		"<strong>${escapeHTML(keyDisplayName(key, index))}</strong>",
		"maskApiKey",
		"keyDisplayName(key, index)",
		"api(PATHS.apiKeyAliases, { method: \"GET\" })",
		":root",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("settings page missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"addKeyButton",
		"credential",
		"delete-key",
		"default_action",
		"models_endpoint",
		"allow_query_keys",
		"id=\"managementKey\"",
		"id=\"authForm\"",
		"style=\"",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("settings page contains removed key-management UI or logic %q", forbidden)
		}
	}
	if strings.Count(body, "api(PATHS.apiKeys") != 1 || !strings.Contains(body, `api(PATHS.apiKeys, { method: "GET" })`) {
		t.Fatal("settings page must access CPA API keys through one read-only GET call")
	}
	if strings.Contains(body, "localStorage.setItem(CPAMC_AUTH_KEY") {
		t.Fatal("settings page must never copy the CPAMC Management Key into local storage")
	}
	for _, writeMethod := range []string{`method: "PUT"`, `method: "PATCH"`, `method: "DELETE"`} {
		apiKeyWrite := regexp.MustCompile(`(?s)api\(PATHS\.apiKeys.{0,160}` + regexp.QuoteMeta(writeMethod))
		if apiKeyWrite.MatchString(body) {
			t.Fatalf("settings page writes to CPA API keys with %s", writeMethod)
		}
	}

	csp := response.Headers.Get("Content-Security-Policy")
	match := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(csp)
	if len(match) != 2 || match[1] == "" {
		t.Fatalf("CSP nonce missing: %q", csp)
	}
	if !strings.Contains(body, `nonce="`+match[1]+`"`) {
		t.Fatal("CSP nonce does not match embedded assets")
	}
	if !strings.Contains(csp, "form-action 'none'") || !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Fatalf("CSP does not allow only same-origin embedding: %q", csp)
	}
	if response.Headers.Get("Cache-Control") != "no-store" || response.Headers.Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Fatalf("security headers = %#v", response.Headers)
	}
}

func TestHandleManagementServesSettingsResource(t *testing.T) {
	request, _ := json.Marshal(managementRequest{Method: http.MethodGet, Path: settingsResourcePath})
	raw, err := handleManagement(request)
	if err != nil {
		t.Fatalf("handleManagement() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Headers.Get("Content-Type"), "text/html") {
		t.Fatalf("settings response = %#v", response)
	}
}

func TestManagementPoliciesReturnsSafeV2DocumentWhenFailClosed(t *testing.T) {
	globalState.clear()
	t.Cleanup(globalState.clear)
	globalState.failClosedOrPreserve(pluginConfig{Version: 1}, schemaVersion, errTestPolicy)

	raw, err := managementPolicies()
	if err != nil {
		t.Fatalf("managementPolicies() error = %v", err)
	}
	var response managementResponse
	unwrapEnvelope(t, raw, &response)
	if string(response.Body) == "" || strings.Contains(string(response.Body), `"version":1`) {
		t.Fatalf("unsafe fail-closed policy response: %s", response.Body)
	}
	if !strings.Contains(string(response.Body), `"version":2`) || !strings.Contains(string(response.Body), `"policies":[]`) {
		t.Fatalf("unexpected fail-closed policy response: %s", response.Body)
	}
}

func TestPolicyRevisionRejectsStaleWrites(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{{CallerScope: scopeA, AllowModels: []string{"*"}}}})
	initialRevision := globalState.policyRevision()
	body := []byte(`{"version":2,"policies":[{"caller_scope":"` + scopeB + `","allow_models":["gpt-*"],"deny_models":[]}]}`)

	raw, err := managementReplacePolicies(body, etagForRevision(initialRevision))
	if err != nil {
		t.Fatalf("matching revision update error = %v", err)
	}
	var updated managementResponse
	unwrapEnvelope(t, raw, &updated)
	if updated.StatusCode != http.StatusOK || globalState.policyRevision() <= initialRevision {
		t.Fatalf("matching revision response = %#v", updated)
	}

	raw, err = managementReplacePolicies(body, etagForRevision(initialRevision))
	if err != nil {
		t.Fatalf("stale revision call error = %v", err)
	}
	var stale managementResponse
	unwrapEnvelope(t, raw, &stale)
	if stale.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("stale revision status = %d body = %s", stale.StatusCode, stale.Body)
	}
}

var errTestPolicy = &testPolicyError{}

type testPolicyError struct{}

func (*testPolicyError) Error() string { return "test invalid policy" }
