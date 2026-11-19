package main

import (
	"encoding/json"
	"net/http"
	"net/url"
)

const (
	abiVersion              uint32 = 1
	rpcSchemaVersion        uint32 = 10
	minimumRPCSchemaVersion uint32 = 10 // The supported CPA v8 host generation.
	policySchemaVersion            = 2  // Persisted policy format, independent of RPC.
	pluginID                       = "key-model-access"
)

var pluginVersion = "0.2.1"

const (
	methodPluginRegister         = "plugin.register"
	methodPluginReconfigure      = "plugin.reconfigure"
	methodRequestInterceptBefore = "request.intercept_before"
	methodRequestInterceptAfter  = "request.intercept_after"
	methodResponseInterceptAfter = "response.intercept_after"
	methodManagementRegister     = "management.register"
	methodManagementHandle       = "management.handle"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type registration struct {
	SchemaVersion uint32       `json:"schema_version"`
	Metadata      metadata     `json:"metadata"`
	Capabilities  capabilities `json:"capabilities"`
}

type metadata struct {
	Name             string        `json:"Name"`
	Version          string        `json:"Version"`
	Author           string        `json:"Author"`
	GitHubRepository string        `json:"GitHubRepository"`
	Logo             string        `json:"Logo"`
	ConfigFields     []configField `json:"ConfigFields"`
}

type configField struct {
	Name        string   `json:"Name"`
	Type        string   `json:"Type"`
	EnumValues  []string `json:"EnumValues,omitempty"`
	Description string   `json:"Description"`
}

type capabilities struct {
	RequestInterceptor  bool `json:"request_interceptor"`
	ResponseInterceptor bool `json:"response_interceptor"`
	ManagementAPI       bool `json:"management_api"`
}

type responseInterceptRequest struct {
	Model           string
	RequestedModel  string
	OriginalRequest []byte
	RequestBody     []byte
	StatusCode      int
	Stream          bool
	Kind            string
	SourceFormat    string
	Body            []byte
	Metadata        map[string]any
}

type responseInterceptResponse struct {
	Headers      http.Header `json:",omitempty"`
	Body         []byte      `json:",omitempty"`
	ClearHeaders []string    `json:",omitempty"`
}

type requestInterceptRequest struct {
	RequestID      string         `json:"RequestID"`
	TraceID        string         `json:"TraceID"`
	SourceFormat   string         `json:"SourceFormat"`
	ToFormat       string         `json:"ToFormat"`
	Model          string         `json:"Model"`
	RequestedModel string         `json:"RequestedModel"`
	Stream         bool           `json:"Stream"`
	Headers        http.Header    `json:"Headers"`
	Body           []byte         `json:"Body"`
	Metadata       map[string]any `json:"Metadata"`
}

type requestInterceptResponse struct {
	Headers         http.Header `json:"Headers,omitempty"`
	Body            []byte      `json:"Body,omitempty"`
	ClearHeaders    []string    `json:"ClearHeaders,omitempty"`
	Terminate       bool        `json:"Terminate,omitempty"`
	StatusCode      int         `json:"StatusCode,omitempty"`
	ResponseHeaders http.Header `json:"ResponseHeaders,omitempty"`
	ResponseBody    []byte      `json:"ResponseBody,omitempty"`
}

type managementRegistrationResponse struct {
	Routes    []managementRoute `json:"routes,omitempty"`
	Resources []resourceRoute   `json:"resources,omitempty"`
}

type managementRoute struct {
	Method      string `json:"Method"`
	Path        string `json:"Path"`
	Description string `json:"Description,omitempty"`
}

type resourceRoute struct {
	Path        string `json:"Path"`
	Menu        string `json:"Menu"`
	Description string `json:"Description,omitempty"`
}

type managementRequest struct {
	Method         string      `json:"Method"`
	Path           string      `json:"Path"`
	Headers        http.Header `json:"Headers"`
	Query          url.Values  `json:"Query"`
	Body           []byte      `json:"Body"`
	HostCallbackID string      `json:"host_callback_id"`
}

type hostAuthModelsResponse struct {
	Credentials []struct {
		Models []string `json:"models"`
	} `json:"credentials"`
}

type managementResponse struct {
	StatusCode int         `json:"StatusCode"`
	Headers    http.Header `json:"Headers,omitempty"`
	Body       []byte      `json:"Body,omitempty"`
}
