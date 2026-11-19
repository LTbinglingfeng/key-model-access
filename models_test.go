package main

import (
	"encoding/json"
	"testing"
)

func TestModelListInterceptor(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{
		{CallerScope: scopeA, AllowModels: []string{"gpt-*"}, DenyModels: []string{"*-preview"}},
	}})
	for _, tc := range []struct {
		name, kind, format, scope, body, want string
	}{
		{"openai deny wins", "model_list", "openai", scopeA,
			`{"object":"list","data":[{"id":"gpt-5","owned_by":"vendor"},{"id":"gpt-5-preview"},{"id":"claude"}]}`,
			`{"data":[{"id":"gpt-5","owned_by":"vendor"}],"object":"list"}`},
		{"codex slug", "model_list", "openai", scopeA,
			`{"models":[{"slug":"gpt-5","priority":1},{"slug":"other"}]}`,
			`{"models":[{"slug":"gpt-5","priority":1}]}`},
		{"claude cloaking and cursor IDs", "model_list", "claude", scopeA,
			`{"data":[{"id":"claude-fable-5-dd-5-tpg"},{"id":"claude-sonnet"}],"has_more":false,"first_id":"claude-fable-5-dd-5-tpg","last_id":"claude-sonnet"}`,
			`{"data":[{"id":"claude-fable-5-dd-5-tpg"}],"first_id":"claude-fable-5-dd-5-tpg","has_more":false,"last_id":"claude-fable-5-dd-5-tpg"}`},
		{"unconfigured key", "model_list", "openai", scopeB, `{"data":[{"id":"other"}]}`, ""},
		{"missing scope", "model_list", "openai", "", `{"data":[{"id":"gpt-5"}]}`, `{"data":[]}`},
		{"malformed catalog", "model_list", "openai", scopeA, `{"data":{}}`, string(emptyModelList("openai"))},
		{"unrelated execution", "execution", "openai", scopeA, `{"data":[{"id":"other"}]}`, ""},
		{"unrelated gemini catalog", "model_list", "gemini", scopeA, `{"models":[{"name":"models/other"}]}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(responseInterceptRequest{
				Kind: tc.kind, SourceFormat: tc.format, Body: []byte(tc.body),
				Metadata: map[string]any{"caller_scope": tc.scope},
			})
			if err != nil {
				t.Fatal(err)
			}
			result, err := handleMethod(methodResponseInterceptAfter, raw)
			if err != nil {
				t.Fatal(err)
			}
			var response responseInterceptResponse
			unwrapEnvelope(t, result, &response)
			if string(response.Body) != tc.want {
				t.Fatalf("body = %s, want %s", response.Body, tc.want)
			}
			if tc.kind == "model_list" && tc.format != "gemini" {
				if got := response.Headers.Get("Cache-Control"); got != "private, no-store" {
					t.Fatalf("Cache-Control = %q", got)
				}
			} else if response.Headers != nil {
				t.Fatalf("unexpected headers: %v", response.Headers)
			}
		})
	}
}
