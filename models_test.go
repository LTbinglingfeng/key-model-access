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
		{"gemini allow and deny", "model_list", "gemini", scopeA,
			`{"models":[{"name":"models/gpt-5","displayName":"GPT"},{"name":"models/gpt-5-preview"},{"name":"models/other","id":"gpt-5"}]}`,
			`{"models":[{"name":"models/gpt-5","displayName":"GPT"}]}`},
		{"gemini missing scope", "model_list", "gemini", "", `{"models":[{"name":"models/gpt-5"}]}`, `{"models":[]}`},
		{"gemini unconfigured key", "model_list", "gemini", scopeB, `{"models":[{"name":"models/other"}]}`, ""},
		{"gemini malformed catalog", "model_list", "gemini", scopeA, `{"models":{}}`, `{"models":[]}`},
		{"unknown format", "model_list", "other", scopeA, `{"models":[]}`, ""},
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
			if tc.kind == "model_list" && tc.format != "other" {
				if got := response.Headers.Get("Cache-Control"); got != "private, no-store" {
					t.Fatalf("Cache-Control = %q", got)
				}
			} else if response.Headers != nil {
				t.Fatalf("unexpected headers: %v", response.Headers)
			}
		})
	}
}

func TestLegacyModelListWithoutKind(t *testing.T) {
	installTestPolicy(t, policyDocument{Version: 2, Policies: []policyConfig{
		{CallerScope: scopeA, AllowModels: []string{"allowed"}},
	}})
	for _, tc := range []struct {
		name, format, model, input, body, want string
	}{
		{"openai list", "openai", "", "", `{"object":"list","data":[{"id":"hidden"}]}`, `{"data":[],"object":"list"}`},
		{"gemini list", "gemini", "", "", `{"models":[{"name":"models/hidden"}]}`, `{"models":[]}`},
		{"codex list", "openai", "", "", `{"models":[{"slug":"hidden"}]}`, `{"models":[]}`},
		{"claude list", "claude", "", "", `{"data":[{"id":"hidden"}]}`, `{"data":[],"first_id":"","last_id":""}`},
		{"execution with list-shaped output", "openai", "allowed", "", `{"data":[{"id":"hidden"}]}`, ""},
		{"execution with input", "openai", "", "{}", `{"models":[]}`, ""},
		{"token count", "claude", "", "", `{"input_tokens":42}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"StatusCode": 200, "SourceFormat": tc.format, "Model": tc.model,
				"OriginalRequest": []byte(tc.input), "Body": []byte(tc.body),
				"Metadata": map[string]string{"caller_scope": scopeA},
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
			if string(response.Body) != tc.want || (tc.want == "" && response.Headers != nil) {
				t.Fatalf("unexpected response: %+v", response)
			}
		})
	}
}
