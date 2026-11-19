package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"
)

func managementModelCatalog(callbackID string) ([]byte, error) {
	if callbackID == "" {
		return managementJSON(http.StatusServiceUnavailable, map[string]string{"error": "CPA model registry is unavailable"})
	}
	catalog, err := hostAuthModels(callbackID)
	if err != nil || catalog.Credentials == nil {
		return managementJSON(http.StatusServiceUnavailable, map[string]string{"error": "CPA model registry is unavailable"})
	}

	seen := make(map[string]struct{})
	for _, credential := range catalog.Credentials {
		for _, model := range credential.Models {
			if model != "" {
				seen[model] = struct{}{}
			}
		}
	}
	models := make([]string, 0, len(seen))
	models = slices.AppendSeq(models, maps.Keys(seen))
	slices.Sort(models)
	return managementJSON(http.StatusOK, map[string][]string{"models": models})
}

func interceptModelList(raw []byte) ([]byte, error) {
	// CPA puts Kind first on the wire. Skip decoding execution payloads.
	if bytes.HasPrefix(raw, []byte(`{"Kind":"execution",`)) ||
		bytes.HasPrefix(raw, []byte(`{"Kind":"count_tokens",`)) {
		return okEnvelope(responseInterceptResponse{})
	}
	var req responseInterceptRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	result := responseInterceptResponse{}
	if (req.SourceFormat != "openai" && req.SourceFormat != "claude" && req.SourceFormat != "gemini") || !isModelList(req) {
		return okEnvelope(result)
	}
	result.Headers = http.Header{"Cache-Control": {"private, no-store"}}

	_, snapshot, _, _, _, _ := globalState.current()
	scope, hasScope := callerScopeFromMetadata(req.Metadata)
	policy, configured := snapshot.ByCallerScope[scope]
	hideAll := snapshot.BlockAll || (len(snapshot.ByCallerScope) > 0 && !hasScope)
	if !hideAll && !configured {
		return okEnvelope(result)
	}

	body := filterModelList(req.Body, req.SourceFormat, policy, hideAll)
	if body != nil {
		result.Body = body
		result.ClearHeaders = []string{"Content-Length", "ETag"}
	}
	return okEnvelope(result)
}

func isModelList(req responseInterceptRequest) bool {
	if req.Kind != "" {
		return req.Kind == "model_list"
	}
	// Before CPA v8.0.78 only the catalog writer sends a successful response
	// with neither model identity nor input body. Check its list envelope too.
	if req.StatusCode != http.StatusOK || req.Stream || req.Model != "" || req.RequestedModel != "" ||
		len(req.OriginalRequest) != 0 || len(req.RequestBody) != 0 {
		return false
	}
	var catalog struct {
		Data   json.RawMessage
		Models json.RawMessage
	}
	if json.Unmarshal(req.Body, &catalog) != nil {
		return false
	}
	if req.SourceFormat == "gemini" {
		return len(catalog.Models) > 0 && catalog.Models[0] == '['
	}
	if req.SourceFormat == "claude" {
		return len(catalog.Data) > 0 && catalog.Data[0] == '['
	}
	return (len(catalog.Data) > 0 && catalog.Data[0] == '[') || (len(catalog.Models) > 0 && catalog.Models[0] == '[')
}

func filterModelList(raw []byte, sourceFormat string, policy runtimePolicy, hideAll bool) []byte {
	var payload map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil {
		return emptyModelList(sourceFormat)
	}

	changed := false
	found := false
	keys := []string{"data", "models"}
	if sourceFormat == "gemini" {
		keys = []string{"models"}
	}
	for _, key := range keys {
		value, exists := payload[key]
		if !exists {
			continue
		}
		found = true
		var items []json.RawMessage
		if json.Unmarshal(value, &items) != nil {
			return emptyModelList(sourceFormat)
		}
		visible := make([]json.RawMessage, 0, len(items))
		var first, last string
		for _, item := range items {
			id := catalogModelID(item, sourceFormat)
			if hideAll || id == "" || !policyAllows(policy, catalogPolicyModel(sourceFormat, id)) {
				continue
			}
			if len(visible) == 0 {
				first = id
			}
			last = id
			visible = append(visible, item)
		}
		if items != nil && len(visible) == len(items) {
			continue
		}
		changed = true
		payload[key], _ = json.Marshal(visible)
		if key == "data" && sourceFormat == "claude" {
			payload["first_id"], _ = json.Marshal(first)
			payload["last_id"], _ = json.Marshal(last)
		}
	}
	if !found {
		return emptyModelList(sourceFormat)
	}
	if !changed {
		return nil
	}
	body, _ := json.Marshal(payload)
	return body
}

func catalogModelID(item json.RawMessage, sourceFormat string) string {
	var entry struct {
		ID   string `json:"id"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if json.Unmarshal(item, &entry) != nil {
		return ""
	}
	if sourceFormat == "gemini" {
		return strings.TrimPrefix(strings.TrimSpace(entry.Name), "models/")
	}
	if id := strings.TrimSpace(entry.ID); id != "" {
		return id
	}
	return strings.TrimSpace(entry.Slug)
}

func catalogPolicyModel(sourceFormat, id string) string {
	// CPA decodes Anthropic's cloaked IDs before applying request interceptors.
	if sourceFormat == "claude" {
		if encoded, ok := strings.CutPrefix(id, "claude-fable-5-dd-"); ok && encoded != "" {
			characters := []rune(encoded)
			slices.Reverse(characters)
			return string(characters)
		}
	}
	return id
}

func emptyModelList(sourceFormat string) []byte {
	if sourceFormat == "gemini" {
		return []byte(`{"models":[]}`)
	}
	if sourceFormat == "claude" {
		return []byte(`{"data":[],"has_more":false,"first_id":"","last_id":""}`)
	}
	return []byte(`{"object":"list","data":[],"models":[]}`)
}
