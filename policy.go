package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

const maxPolicyFileSize = 2 << 20

type pluginConfig struct {
	Enabled    *bool          `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Priority   int            `json:"priority,omitempty" yaml:"priority,omitempty"`
	Store      any            `json:"store,omitempty" yaml:"store,omitempty"`
	PolicyFile string         `json:"policy_file,omitempty" yaml:"policy_file,omitempty"`
	Version    int            `json:"version,omitempty" yaml:"version,omitempty"`
	Policies   []policyConfig `json:"policies,omitempty" yaml:"policies,omitempty"`
}

type policyDocument struct {
	Version  int            `json:"version" yaml:"version" toml:"version"`
	Policies []policyConfig `json:"policies" yaml:"policies" toml:"policies"`
}

type policyConfig struct {
	CallerScope string   `json:"caller_scope" yaml:"caller_scope" toml:"caller_scope"`
	AllowModels []string `json:"allow_models" yaml:"allow_models" toml:"allow_models"`
	DenyModels  []string `json:"deny_models" yaml:"deny_models" toml:"deny_models"`
}

type runtimePolicy struct {
	AllowModels []string
	DenyModels  []string
}

type policySnapshot struct {
	ByCallerScope map[string]runtimePolicy
	BlockAll      bool
}

type state struct {
	mu             sync.RWMutex
	config         pluginConfig
	snapshot       policySnapshot
	source         string
	updatedAt      time.Time
	hostSchema     uint32
	hasValidPolicy bool
	lastError      string
	revision       uint64
}

var (
	globalState = state{snapshot: failClosedSnapshot()}
	mutationMu  sync.Mutex
)

func failClosedSnapshot() policySnapshot {
	return policySnapshot{ByCallerScope: make(map[string]runtimePolicy), BlockAll: true}
}

func (s *state) clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = pluginConfig{}
	s.snapshot = failClosedSnapshot()
	s.source = ""
	s.updatedAt = time.Time{}
	s.hostSchema = 0
	s.hasValidPolicy = false
	s.lastError = ""
	s.revision = 0
}

func (s *state) current() (pluginConfig, policySnapshot, string, time.Time, uint32, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError
}

func (s *state) currentWithRevision() (pluginConfig, policySnapshot, string, time.Time, uint32, string, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config, s.snapshot, s.source, s.updatedAt, s.hostSchema, s.lastError, s.revision
}

func (s *state) replace(cfg pluginConfig, snapshot policySnapshot, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = cfg
	s.snapshot = snapshot
	s.source = source
	s.updatedAt = time.Now().UTC()
	s.hasValidPolicy = true
	s.lastError = ""
	s.revision++
}

func (s *state) policyRevision() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.revision
}

func (s *state) setHostSchema(schema uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
}

func (s *state) recordPolicyError(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = cause.Error()
}

func (s *state) failClosedOrPreserve(cfg pluginConfig, schema uint32, cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hostSchema = schema
	s.lastError = cause.Error()
	if s.hasValidPolicy {
		return
	}
	s.config = cfg
	s.snapshot = failClosedSnapshot()
	s.source = "fail-closed: " + cause.Error()
	s.updatedAt = time.Now().UTC()
	s.revision++
}

func configure(raw []byte) error {
	mutationMu.Lock()
	defer mutationMu.Unlock()

	var req lifecycleRequest
	if err := decodeJSON(raw, &req); err != nil {
		return err
	}
	cfg := pluginConfig{Version: policySchemaVersion}
	if req.SchemaVersion < minimumRPCSchemaVersion {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("%s requires CPA plugin RPC schema 2 or newer (CPA v7.2.103+)", pluginID))
		return nil
	}
	if len(req.ConfigYAML) > 0 {
		if err := decodeStrictYAML(req.ConfigYAML, &cfg); err != nil {
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, fmt.Errorf("decode plugin config: %w", err))
			return nil
		}
	}
	cfg.PolicyFile = strings.TrimSpace(cfg.PolicyFile)

	document := documentFromConfig(cfg)
	source := "inline config"
	if cfg.PolicyFile != "" {
		loaded, err := readPolicyFile(cfg.PolicyFile)
		if err != nil {
			globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
			return nil
		}
		document = loaded
		source = cfg.PolicyFile
	}

	snapshot, sanitized, err := compileDocument(document)
	if err != nil {
		globalState.failClosedOrPreserve(cfg, req.SchemaVersion, err)
		return nil
	}
	cfg.Version = sanitized.Version
	cfg.Policies = sanitized.Policies
	globalState.setHostSchema(req.SchemaVersion)
	globalState.replace(cfg, snapshot, source)
	return nil
}

func documentFromConfig(cfg pluginConfig) policyDocument {
	return policyDocument{Version: cfg.Version, Policies: clonePolicyConfigs(cfg.Policies)}
}

func clonePolicyConfigs(policies []policyConfig) []policyConfig {
	cloned := make([]policyConfig, len(policies))
	for index, policy := range policies {
		cloned[index] = policyConfig{
			CallerScope: policy.CallerScope,
			AllowModels: append([]string{}, policy.AllowModels...),
			DenyModels:  append([]string{}, policy.DenyModels...),
		}
	}
	return cloned
}

func readPolicyFile(path string) (policyDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return policyDocument{}, fmt.Errorf("open policy file %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return policyDocument{}, fmt.Errorf("stat policy file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return policyDocument{}, fmt.Errorf("policy file %q is not a regular file", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPolicyFileSize+1))
	if err != nil {
		return policyDocument{}, fmt.Errorf("read policy file %q: %w", path, err)
	}
	if len(raw) > maxPolicyFileSize {
		return policyDocument{}, fmt.Errorf("policy file %q exceeds %d bytes", path, maxPolicyFileSize)
	}
	var document policyDocument
	var errDecode error
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		errDecode = decodeStrictTOML(raw, &document)
	} else {
		errDecode = decodeStrictYAML(raw, &document)
	}
	if errDecode != nil {
		return policyDocument{}, fmt.Errorf("decode policy file %q: %w", path, errDecode)
	}
	return document, nil
}

func decodeStrictTOML(raw []byte, target any) error {
	metadata, errDecode := toml.Decode(string(raw), target)
	if errDecode != nil {
		return errDecode
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, key := range undecoded {
			keys = append(keys, key.String())
		}
		return fmt.Errorf("unknown TOML fields: %s", strings.Join(keys, ", "))
	}
	return nil
}

func decodeStrictYAML(raw []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return fmt.Errorf("multiple YAML documents are not allowed")
}

func compileDocument(document policyDocument) (policySnapshot, policyDocument, error) {
	if document.Version != policySchemaVersion {
		return policySnapshot{}, policyDocument{}, fmt.Errorf("unsupported policy version %d; only version 2 is supported", document.Version)
	}
	if document.Policies == nil {
		document.Policies = []policyConfig{}
	}

	snapshot := policySnapshot{ByCallerScope: make(map[string]runtimePolicy)}
	for index := range document.Policies {
		item := &document.Policies[index]
		item.CallerScope = strings.ToLower(strings.TrimSpace(item.CallerScope))
		if !validSHA256(item.CallerScope) {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("policies[%d].caller_scope must be 64 hexadecimal characters", index)
		}
		if _, exists := snapshot.ByCallerScope[item.CallerScope]; exists {
			return policySnapshot{}, policyDocument{}, fmt.Errorf("duplicate caller_scope at policies[%d]", index)
		}
		var err error
		item.AllowModels, err = normalizePatterns(item.AllowModels, fmt.Sprintf("policies[%d].allow_models", index))
		if err != nil {
			return policySnapshot{}, policyDocument{}, err
		}
		item.DenyModels, err = normalizePatterns(item.DenyModels, fmt.Sprintf("policies[%d].deny_models", index))
		if err != nil {
			return policySnapshot{}, policyDocument{}, err
		}
		snapshot.ByCallerScope[item.CallerScope] = runtimePolicy{
			AllowModels: append([]string(nil), item.AllowModels...),
			DenyModels:  append([]string(nil), item.DenyModels...),
		}
	}
	return snapshot, document, nil
}

func normalizePatterns(patterns []string, field string) ([]string, error) {
	seen := make(map[string]struct{}, len(patterns))
	out := make([]string, 0, len(patterns))
	for index, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("%s[%d] must not be empty", field, index)
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out, nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// callerScope mirrors CPA's built-in API-key identity derivation. It is kept
// here for fixed-vector tests and operator tooling; raw keys are never accepted
// by the policy schema or Management API.
func callerScope(rawKey string) string {
	sum := sha256.Sum256([]byte("cli-proxy-api:caller-scope:v1\x00" + strings.TrimSpace(rawKey)))
	return hex.EncodeToString(sum[:])
}

func policyAllows(policy runtimePolicy, model string) bool {
	model = strings.TrimSpace(model)
	for _, pattern := range policy.DenyModels {
		if wildcardMatch(pattern, model) {
			return false
		}
	}
	if len(policy.AllowModels) == 0 {
		return true
	}
	for _, pattern := range policy.AllowModels {
		if wildcardMatch(pattern, model) {
			return true
		}
	}
	return false
}

// wildcardMatch supports shell-style '*' and '?' while allowing '*' to cross '/'.
func wildcardMatch(pattern, value string) bool {
	patternRunes, valueRunes := []rune(pattern), []rune(value)
	p, v, star, checkpoint := 0, 0, -1, 0
	for v < len(valueRunes) {
		if p < len(patternRunes) && (patternRunes[p] == '?' || patternRunes[p] == valueRunes[v]) {
			p++
			v++
			continue
		}
		if p < len(patternRunes) && patternRunes[p] == '*' {
			star = p
			p++
			checkpoint = v
			continue
		}
		if star >= 0 {
			p = star + 1
			checkpoint++
			v = checkpoint
			continue
		}
		return false
	}
	for p < len(patternRunes) && patternRunes[p] == '*' {
		p++
	}
	return p == len(patternRunes)
}

func writePolicyFile(path string, document policyDocument) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("policy_file is not configured")
	}
	var raw []byte
	var err error
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		if len(document.Policies) == 0 {
			raw = []byte("version = 2\npolicies = []\n")
		} else {
			raw, err = toml.Marshal(document)
		}
	} else {
		raw, err = yaml.Marshal(document)
	}
	if err != nil {
		return fmt.Errorf("encode policy file: %w", err)
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create policy directory: %w", err)
		}
	}
	temporary, err := os.CreateTemp(dir, ".key-model-access-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary policy file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("secure temporary policy file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write temporary policy file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync temporary policy file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary policy file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace policy file: %w", err)
	}
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("open policy directory for sync: %w", err)
		}
		errSync := directory.Sync()
		errClose := directory.Close()
		if errSync != nil {
			return fmt.Errorf("sync policy directory: %w", errSync)
		}
		if errClose != nil {
			return fmt.Errorf("close policy directory: %w", errClose)
		}
	}
	return nil
}
