package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	policiesPath          = "/v0/management/plugins/key-model-access/policies"
	statusPath            = "/v0/management/plugins/key-model-access/status"
	reloadPath            = "/v0/management/plugins/key-model-access/reload"
	initializeStoragePath = "/v0/management/plugins/key-model-access/initialize-storage"
	settingsResourcePath  = "/v0/resource/plugins/key-model-access/settings"
)

func interceptRequest(raw []byte) ([]byte, error) {
	var req requestInterceptRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	model := strings.TrimSpace(req.RequestedModel)
	if model == "" {
		model = strings.TrimSpace(req.Model)
	}

	_, snapshot, _, _, _, _ := globalState.current()
	if snapshot.BlockAll {
		return terminatedPolicyResponse(http.StatusForbidden, "model access policy is unavailable", model)
	}

	scope, hasScope := callerScopeFromMetadata(req.Metadata)
	if len(snapshot.ByCallerScope) > 0 && !hasScope {
		return terminatedPolicyResponse(http.StatusForbidden, "model access identity is unavailable", model)
	}
	if !hasScope {
		return okEnvelope(requestInterceptResponse{})
	}
	policy, configured := snapshot.ByCallerScope[scope]
	if !configured {
		return okEnvelope(requestInterceptResponse{})
	}
	if model == "" {
		return terminatedPolicyResponse(http.StatusForbidden, "requested model is unavailable for policy evaluation", "")
	}
	if !policyAllows(policy, model) {
		return terminatedPolicyResponse(http.StatusForbidden, "model is not allowed for this API key", model)
	}
	return okEnvelope(requestInterceptResponse{})
}

func callerScopeFromMetadata(metadata map[string]any) (string, bool) {
	raw, ok := metadata["caller_scope"].(string)
	if !ok {
		return "", false
	}
	scope := strings.ToLower(strings.TrimSpace(raw))
	return scope, validSHA256(scope)
}

func terminatedPolicyResponse(status int, message, model string) ([]byte, error) {
	details := map[string]any{
		"type":    "model_access_denied",
		"message": message,
	}
	if model != "" {
		details["model"] = model
	}
	body, err := json.Marshal(map[string]any{"error": details})
	if err != nil {
		return nil, err
	}
	return okEnvelope(requestInterceptResponse{
		Terminate:       true,
		StatusCode:      status,
		ResponseHeaders: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}},
		ResponseBody:    body,
	})
}

func managementRegistration() managementRegistrationResponse {
	return managementRegistrationResponse{
		Routes: []managementRoute{
			{Method: http.MethodGet, Path: statusPath, Description: "Show key-model-access status without exposing API keys or caller scopes."},
			{Method: http.MethodGet, Path: policiesPath, Description: "List caller-scope model policies."},
			{Method: http.MethodPut, Path: policiesPath, Description: "Replace all caller-scope model policies."},
			{Method: http.MethodPost, Path: reloadPath, Description: "Reload policies from policy_file."},
			{Method: http.MethodPost, Path: initializeStoragePath, Description: "Create or validate the default plugin-owned TOML policy file."},
		},
		Resources: []resourceRoute{{
			Path:        "/settings",
			Menu:        "模型权限",
			Description: "Manage per-key model access policies in a browser.",
		}},
	}
}

func handleManagement(raw []byte) ([]byte, error) {
	var req managementRequest
	if err := decodeJSON(raw, &req); err != nil {
		return nil, err
	}
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	path := strings.TrimRight(strings.TrimSpace(req.Path), "/")
	switch {
	case method == http.MethodGet && path == settingsResourcePath:
		return settingsPage()
	case method == http.MethodGet && path == statusPath:
		return managementStatus()
	case method == http.MethodGet && path == policiesPath:
		return managementPolicies()
	case method == http.MethodPut && path == policiesPath:
		return managementReplacePolicies(req.Body, req.Headers.Get("If-Match"))
	case method == http.MethodPost && path == reloadPath:
		return managementReload()
	case method == http.MethodPost && path == initializeStoragePath:
		return managementInitializeStorage(req.Body)
	default:
		return managementJSON(http.StatusNotFound, map[string]any{"error": "management route not found"})
	}
}

func managementStatus() ([]byte, error) {
	cfg, snapshot, source, updatedAt, hostSchema, lastError, revision := globalState.currentWithRevision()
	return managementJSON(http.StatusOK, map[string]any{
		"plugin":                  pluginID,
		"version":                 pluginVersion,
		"schema_version":          rpcSchemaVersion,
		"policy_schema_version":   policySchemaVersion,
		"host_schema_version":     hostSchema,
		"auth_mode":               "cpa_builtin_api_keys",
		"identity_source":         "Metadata.caller_scope",
		"unconfigured_key_action": "allow",
		"last_error":              lastError,
		"policy_count":            len(snapshot.ByCallerScope),
		"revision":                revision,
		"policy_file":             cfg.PolicyFile,
		"persistent_updates":      cfg.PolicyFile != "",
		"source":                  source,
		"updated_at":              formattedTime(updatedAt),
		"fail_closed":             snapshot.BlockAll,
	})
}

func managementPolicies() ([]byte, error) {
	cfg, snapshot, source, updatedAt, _, _, revision := globalState.currentWithRevision()
	document := policyDocument{Version: policySchemaVersion, Policies: []policyConfig{}}
	if !snapshot.BlockAll {
		document = documentFromConfig(cfg)
	}
	return managementJSONWithHeaders(http.StatusOK, map[string]any{
		"policy":     document,
		"revision":   revision,
		"source":     source,
		"updated_at": formattedTime(updatedAt),
	}, http.Header{"ETag": []string{etagForRevision(revision)}})
}

func managementReplacePolicies(body []byte, ifMatch string) ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	if strings.TrimSpace(ifMatch) != "" {
		expected, err := parseRevisionETag(ifMatch)
		if err != nil {
			return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		}
		current := globalState.policyRevision()
		if expected != current {
			return managementJSON(http.StatusPreconditionFailed, map[string]any{
				"error":            "policy changed since it was loaded; reload before saving",
				"current_revision": current,
			})
		}
	}

	if len(body) == 0 || len(body) > maxPolicyFileSize {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("policy body must be between 1 and %d bytes", maxPolicyFileSize)})
	}
	var document policyDocument
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "invalid policy JSON: " + err.Error()})
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
	}
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}

	cfg, _, _, _, _, _ := globalState.current()
	if cfg.PolicyFile != "" {
		if err := writePolicyFile(cfg.PolicyFile, sanitized); err != nil {
			return managementJSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
	}
	cfg.Version = sanitized.Version
	cfg.Policies = clonePolicyConfigs(sanitized.Policies)
	source := "Management API (memory only)"
	if cfg.PolicyFile != "" {
		source = cfg.PolicyFile
	}
	globalState.replace(cfg, snapshot, source)
	revision := globalState.policyRevision()
	return managementJSONWithHeaders(http.StatusOK, map[string]any{
		"ok":           true,
		"policy_count": len(snapshot.ByCallerScope),
		"persistent":   cfg.PolicyFile != "",
		"revision":     revision,
		"policy":       sanitized,
	}, http.Header{"ETag": []string{etagForRevision(revision)}})
}

func managementInitializeStorage(body []byte) ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	if len(body) == 0 || len(body) > 4096 {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "plugins_dir request is required"})
	}
	var request struct {
		PluginsDir string `json:"plugins_dir"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "invalid storage initialization body: " + err.Error()})
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
	}
	pluginsDir := strings.TrimSpace(request.PluginsDir)
	if pluginsDir == "" || strings.ContainsRune(pluginsDir, '\x00') {
		return managementJSON(http.StatusBadRequest, map[string]any{"error": "plugins_dir must be a non-empty filesystem path"})
	}
	pluginsDir = filepath.Clean(pluginsDir)
	if !pluginBinaryExists(pluginsDir) {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": "plugins_dir does not contain the installed key-model-access binary"})
	}
	policyDir := filepath.Join(pluginsDir, pluginID)
	if info, errStat := os.Lstat(policyDir); errStat == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return managementJSON(http.StatusConflict, map[string]any{"error": "default policy directory exists but is not a regular directory"})
		}
	} else if !os.IsNotExist(errStat) {
		return managementJSON(http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("inspect default policy directory: %v", errStat)})
	}
	policyPath := filepath.Join(policyDir, "config.toml")
	created := false
	info, errStat := os.Lstat(policyPath)
	switch {
	case errStat == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return managementJSON(http.StatusConflict, map[string]any{"error": "default policy path exists but is not a regular file"})
		}
	case os.IsNotExist(errStat):
		cfg, snapshot, _, _, _, _ := globalState.current()
		if snapshot.BlockAll {
			return managementJSON(http.StatusConflict, map[string]any{"error": "cannot initialize storage while the active policy is fail-closed"})
		}
		document := documentFromConfig(cfg)
		if _, sanitized, errCompile := compileDocument(document); errCompile != nil {
			return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": errCompile.Error()})
		} else if errWrite := writePolicyFile(policyPath, sanitized); errWrite != nil {
			return managementJSON(http.StatusInternalServerError, map[string]any{"error": errWrite.Error()})
		}
		created = true
	default:
		return managementJSON(http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("inspect default policy path: %v", errStat)})
	}

	document, errRead := readPolicyFile(policyPath)
	if errRead != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": errRead.Error()})
	}
	_, sanitized, errCompile := compileDocument(document)
	if errCompile != nil {
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": errCompile.Error()})
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return managementJSON(status, map[string]any{
		"created":      created,
		"policy_file":  policyPath,
		"policy_count": len(sanitized.Policies),
	})
}

func pluginBinaryExists(pluginsDir string) bool {
	extension := ".so"
	switch runtime.GOOS {
	case "darwin":
		extension = ".dylib"
	case "windows":
		extension = ".dll"
	}
	candidateDirs := []string{
		filepath.Join(pluginsDir, runtime.GOOS, runtime.GOARCH),
		pluginsDir,
	}
	for _, dir := range candidateDirs {
		entries, errRead := os.ReadDir(dir)
		if errRead != nil {
			continue
		}
		for _, entry := range entries {
			if entry == nil || !entry.Type().IsRegular() {
				continue
			}
			name := entry.Name()
			lowerName := strings.ToLower(name)
			if !strings.HasSuffix(lowerName, extension) {
				continue
			}
			base := name[:len(name)-len(extension)]
			if base == pluginID || (strings.HasPrefix(base, pluginID+"-v") && len(base) > len(pluginID)+2) {
				return true
			}
		}
	}
	return false
}

func managementReload() ([]byte, error) {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	cfg, _, _, _, _, _ := globalState.current()
	if cfg.PolicyFile == "" {
		return managementJSON(http.StatusConflict, map[string]any{"error": "policy_file is not configured"})
	}
	document, err := readPolicyFile(cfg.PolicyFile)
	if err != nil {
		globalState.recordPolicyError(err)
		return managementJSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
	}
	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		globalState.recordPolicyError(err)
		return managementJSON(http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
	}
	cfg.Version = sanitized.Version
	cfg.Policies = clonePolicyConfigs(sanitized.Policies)
	globalState.replace(cfg, snapshot, cfg.PolicyFile)
	return managementJSON(http.StatusOK, map[string]any{
		"ok": true, "policy_count": len(snapshot.ByCallerScope), "revision": globalState.policyRevision(),
	})
}

func managementJSON(status int, value any) ([]byte, error) {
	return managementJSONWithHeaders(status, value, nil)
}

func managementJSONWithHeaders(status int, value any, extra http.Header) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	headers := http.Header{"Content-Type": []string{"application/json; charset=utf-8"}, "Cache-Control": []string{"no-store"}}
	for name, values := range extra {
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	return okEnvelope(managementResponse{StatusCode: status, Headers: headers, Body: body})
}

func etagForRevision(revision uint64) string {
	return fmt.Sprintf("\"rev-%d\"", revision)
}

func parseRevisionETag(value string) (uint64, error) {
	value = strings.Trim(strings.TrimSpace(value), "\"")
	value = strings.TrimPrefix(value, "rev-")
	if value == "" {
		return 0, fmt.Errorf("If-Match must contain a policy revision ETag")
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid policy revision ETag")
	}
	return revision, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return fmt.Errorf("policy body must contain one JSON object")
}

func formattedTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
