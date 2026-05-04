//go:build unit

package tools

import (
	"context"
	"encoding/json"
	"testing"

	mcpgrafana "github.com/grafana/mcp-grafana"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeURLTestCtx(grafanaURL, publicURL string) context.Context {
	cfg := mcpgrafana.GrafanaConfig{URL: grafanaURL}
	ctx := mcpgrafana.WithGrafanaConfig(context.Background(), cfg)
	if publicURL != "" {
		ctx = mcpgrafana.WithGrafanaClient(ctx, &mcpgrafana.GrafanaClient{PublicURL: publicURL})
	}
	return ctx
}

// ---- appendJSONDataStringCandidates ----

func TestAppendJSONDataStringCandidates(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  []string
	}{
		{
			name:  "plain string",
			input: "hello",
			want:  []string{"hello"},
		},
		{
			name:  "slice of strings",
			input: []any{"a", "b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "map of strings",
			input: map[string]any{"k1": "v1", "k2": "v2"},
			want:  []string{"v1", "v2"},
		},
		{
			name:  "nested slice",
			input: []any{"top", []any{"nested1", "nested2"}},
			want:  []string{"top", "nested1", "nested2"},
		},
		{
			name:  "nested map",
			input: map[string]any{"outer": map[string]any{"inner": "deep"}},
			want:  []string{"deep"},
		},
		{
			name:  "non-string value ignored",
			input: 42,
			want:  []string{},
		},
		{
			name:  "slice with mixed types ignores non-strings",
			input: []any{"keep", 99, true},
			want:  []string{"keep"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendJSONDataStringCandidates([]string{}, tt.input)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

// ---- matchesAuthIntent ----

func TestMatchesAuthIntent_Blocked(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		// datasourceOrGrafanaContext + authSetupVerbThenAuthPhrase
		{"add auth to prometheus", "add authentication to the prometheus datasource"},
		{"configure auth for grafana", "configure authentication for grafana"},
		{"enable credentials loki", "enable credentials for loki"},
		{"set up basic auth grafana", "set up basic auth for grafana"},
		{"implement auth datasource", "implement auth for my datasource"},
		{"turn on auth elasticsearch", "turn on authentication for elasticsearch"},

		// datasourceOrGrafanaContext + authPhraseTowardBackend
		{"auth for prometheus", "auth for the prometheus datasource"},
		{"authentication to grafana", "authentication to grafana"},
		{"auth on loki datasource", "auth on loki datasource"},
		{"authentication with tempo", "authentication with tempo"},

		// authIntentPatterns[0]: add … authentication
		{"add authentication", "add authentication"},
		{"add basic authentication", "add basic authentication"},
		{"add mTLS authentication", "add mTLS authentication"},

		// authIntentPatterns[1]: add/enable/configure/set up/turn on … basic auth
		{"add basic auth", "add basic auth"},
		{"enable basic auth", "enable basic auth"},
		{"configure basic authentication", "configure basic authentication"},
		{"set up basic auth", "set up basic auth"},
		{"turn on basic auth", "turn on basic auth"},

		// authIntentPatterns[2]: basic auth to/for/on datasource/grafana/instance
		{"basic auth to datasource", "basic auth to my datasource"},
		{"basic auth for grafana", "basic auth for grafana"},
		{"basic authentication on instance", "basic authentication on instance"},

		// authIntentPatterns[3]: authentication with … username/password/credential
		{"authentication with username", "authentication with username"},
		{"authentication with password", "authentication with password"},
		{"authentication with credential", "authentication with credential"},

		// authIntentPatterns[4]: username and password
		{"username and password", "username and password"},
		{"user name and password", "user name and password"},

		// authIntentPatterns[5]: basic/digest auth … with/using … user/pass/credential
		{"basic auth with user", "basic auth with user"},
		{"digest auth using password", "digest auth using password"},
		{"basic auth with credential", "basic auth with credential"},

		// authIntentPatterns[6]: basic/digest auth … datasource/grafana
		{"basic auth grafana", "basic auth grafana"},
		{"digest auth datasource", "digest auth datasource"},
		{"basic authentication data source", "basic authentication data source"},

		// authIntentPatterns[7]: enable … auth … password/credential/username
		{"enable auth password", "enable auth password"},
		{"enable basic auth with credential", "enable basic auth with credential"},
		{"enable auth with username", "enable auth with username"},

		// authIntentPatterns[8]: configure … credentials/auth … password/token/secret/username
		{"configure credentials with password", "configure credentials with password"},
		{"configure auth with token", "configure auth with token"},
		{"configure authentication with secret", "configure authentication with secret"},
		{"configure credentials with username", "configure credentials with username"},

		// authIntentPatterns[9]: store/save/paste/inject … password/api key/token/secret
		{"store password", "store my password"},
		{"save api key", "save api key"},
		{"paste access token", "paste access token"},
		{"inject bearer token", "inject bearer token"},
		{"paste secret", "paste my secret"},

		// authIntentPatterns[10]: log in with password/username
		{"log in with password", "log in with my password"},
		{"login with username", "login with username"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, matchesAuthIntent(tt.text), "expected auth intent match for: %q", tt.text)
		})
	}
}

func TestMatchesAuthIntent_Allowed(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"empty string", ""},
		{"whitespace", "   "},
		{"list datasources", "list all grafana datasources"},
		{"show prometheus config", "show me the prometheus configuration"},
		{"ask about url", "what is the URL of the loki datasource"},
		{"plain uid", "abc-123"},
		{"datasource name only", "prometheus"},
		{"update url field", "update the url of the datasource"},
		{"get datasource type", "what type is this datasource"},
		{"plain json data key", "httpMethod"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, matchesAuthIntent(tt.text), "unexpected auth intent match for: %q", tt.text)
		})
	}
}

// ---- matchesSecretLike ----

func TestMatchesSecretLike_Blocked(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		// RSA/EC/DSA/OPENSSH private key headers
		{"rsa private key", "-----BEGIN RSA PRIVATE KEY-----"},
		{"ec private key", "-----BEGIN EC PRIVATE KEY-----"},
		{"dsa private key", "-----BEGIN DSA PRIVATE KEY-----"},
		{"openssh private key", "-----BEGIN OPENSSH PRIVATE KEY-----"},
		{"generic private key", "-----BEGIN PRIVATE KEY-----"},
		{"private key block", "-----BEGIN PRIVATE KEY BLOCK-----"},

		// AWS access key IDs (AKIA + 16 uppercase alphanumeric)
		{"aws akia key", "AKIAIOSFODNN7EXAMPLE"},
		{"aws key in sentence", "my key is AKIAIOSFODNN7EXAMPLE and more"},

		// GitHub personal access token (ghp_ + 36 alphanumeric)
		{"github pat", "ghp_abcdefghijklmnopqrstuvwxyz1234567890"},
		{"github pat in sentence", "token: ghp_abcdefghijklmnopqrstuvwxyz1234567890"},

		// GitHub server-to-server token (ghs_ + 36 alphanumeric)
		{"github server token", "ghs_abcdefghijklmnopqrstuvwxyz1234567890"},

		// GitLab PAT (glpat- + 20+ alphanumeric/hyphen)
		{"gitlab pat", "glpat-abcdefghijklmnopqrst"},
		{"gitlab pat long", "glpat-abcdefghijklmnopqrstuvwxyz"},

		// Slack tokens (xox[baprs]- + 10+ alphanumeric/hyphen)
		{"slack bot token", "xoxb-1234567890-abcdefghij"},
		{"slack app token", "xoxa-1234567890-abcdefghij"},
		{"slack user token", "xoxp-1234567890-abcdefghij"},
		{"slack refresh token", "xoxr-1234567890-abcdefghij"},
		{"slack workspace token", "xoxs-1234567890-abcdefghij"},

		// password/passwd/api_key/secret_key/auth_token = value (8+ chars)
		{"password equals", "password=supersecret123"},
		{"passwd colon", "passwd: supersecret"},
		{"api key equals", "api_key=abcdefgh"},
		{"api-key equals", "api-key=abcdefgh"},
		{"secret key equals", "secret_key=abcdefgh"},
		{"auth token equals", "auth_token=abcdefgh"},
		{"password colon spaced", "password: my-long-password"},

		// Bearer token (20+ chars)
		{"bearer token", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"bearer token short long value", "Bearer abcdefghijklmnopqrstu"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.True(t, matchesSecretLike(tt.text), "expected secret match for: %q", tt.text)
		})
	}
}

func TestMatchesSecretLike_Allowed(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"empty string", ""},
		{"plain url", "http://prometheus:9090"},
		{"datasource name", "My Prometheus"},
		{"plain uid", "abc-123-uid"},
		{"json data key", "httpMethod"},
		{"short password field", "password=abc"},                         // under 8 chars after =
		{"aws key too short", "AKIAIOSFODNN7EXAMP"},                      // only 18 chars after AKIA
		{"github pat too short", "ghp_abcdefghijklmnopqrstuvwxyz123456"}, // 35 chars, needs 36
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, matchesSecretLike(tt.text), "unexpected secret match for: %q", tt.text)
		})
	}
}

// ---- checkDatasourceCredentials ----

func TestCheckDatasourceCredentials(t *testing.T) {
	tests := []struct {
		name   string
		args   CreateDatasourceParams
		wantOK bool
		reason string
	}{
		{
			name:   "clean params allowed",
			args:   CreateDatasourceParams{Name: "Prometheus", Type: "prometheus", URL: "http://prometheus:9090"},
			wantOK: true,
		},
		{
			name:   "basicAuth true not blocked",
			args:   CreateDatasourceParams{Name: "test", Type: "prometheus", BasicAuth: true},
			wantOK: true,
		},
		{
			name:   "basicAuthUser blocked",
			args:   CreateDatasourceParams{Name: "test", Type: "prometheus", BasicAuthUser: "user"},
			reason: "basic_auth_user_via_mcp_disallowed",
		},
		{
			name:   "secureJsonData blocked",
			args:   CreateDatasourceParams{Name: "test", Type: "prometheus", SecureJSONData: map[string]string{"token": "abc"}},
			reason: "secure_json_data_found",
		},
		{
			name:   "auth intent in name blocked",
			args:   CreateDatasourceParams{Name: "add authentication to grafana datasource", Type: "prometheus"},
			reason: "auth_credential_instructions",
		},
		{
			name:   "auth intent in database field blocked",
			args:   CreateDatasourceParams{Name: "test", Type: "postgres", Database: "configure credentials with username and password"},
			reason: "auth_credential_instructions",
		},
		{
			name:   "private key in jsonData blocked",
			args:   CreateDatasourceParams{Name: "test", Type: "prometheus", JSONData: map[string]interface{}{"key": "-----BEGIN RSA PRIVATE KEY-----"}},
			reason: "embedded_secret_or_token",
		},
		{
			name: "nested secret in jsonData blocked",
			args: CreateDatasourceParams{
				Name: "test",
				Type: "prometheus",
				JSONData: map[string]interface{}{
					"auth": map[string]interface{}{
						"token": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
					},
				},
			},
			reason: "embedded_secret_or_token",
		},
		{
			name: "auth intent in nested jsonData array blocked",
			args: CreateDatasourceParams{
				Name: "test",
				Type: "prometheus",
				JSONData: map[string]interface{}{
					"steps": []interface{}{
						"noop",
						map[string]interface{}{"instruction": "configure credentials with username and password"},
					},
				},
			},
			reason: "auth_credential_instructions",
		},
		{
			name:   "bearer token in URL blocked",
			args:   CreateDatasourceParams{Name: "test", Type: "prometheus", URL: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature123"},
			reason: "embedded_secret_or_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkDatasourceCredentials(tt.args)
			if tt.wantOK {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tt.reason, got)
			}
		})
	}
}

// ---- datasourceConfigPageURL ----

func TestDatasourceConfigPageURL(t *testing.T) {
	tests := []struct {
		name       string
		grafanaURL string
		publicURL  string
		uid        string
		want       string
	}{
		{
			name:       "no uid → new page",
			grafanaURL: "http://localhost:3000",
			want:       "http://localhost:3000/connections/datasources/new",
		},
		{
			name:       "uid → edit page",
			grafanaURL: "http://localhost:3000",
			uid:        "abc-123",
			want:       "http://localhost:3000/connections/datasources/edit/abc-123",
		},
		{
			name:       "uid with slashes is path-escaped",
			grafanaURL: "http://localhost:3000",
			uid:        "prom/uid",
			want:       "http://localhost:3000/connections/datasources/edit/prom%2Fuid",
		},
		{
			name:       "prefers public URL over config URL",
			grafanaURL: "http://internal:3000",
			publicURL:  "https://grafana.example.com",
			want:       "https://grafana.example.com/connections/datasources/new",
		},
		{
			name:      "falls back to public URL when config URL is empty",
			publicURL: "https://grafana.example.com",
			want:      "https://grafana.example.com/connections/datasources/new",
		},
		{
			name:       "https config URL supported",
			grafanaURL: "https://grafana.example.com",
			want:       "https://grafana.example.com/connections/datasources/new",
		},
		{
			name:       "config URL sub-path is preserved",
			grafanaURL: "https://grafana.example.com/grafana",
			want:       "https://grafana.example.com/grafana/connections/datasources/new",
		},
		{
			name:      "public URL sub-path is preserved when config URL is empty",
			publicURL: "https://grafana.example.com/grafana",
			uid:       "prometheus",
			want:      "https://grafana.example.com/grafana/connections/datasources/edit/prometheus",
		},
		{
			name: "empty URL returns empty string",
			want: "",
		},
		{
			name:       "invalid scheme returns empty string",
			grafanaURL: "ftp://grafana.example.com",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := makeURLTestCtx(tt.grafanaURL, tt.publicURL)
			got := datasourceConfigPageURL(ctx, tt.uid)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---- credentialViolationResult ----

func TestCredentialViolationResult(t *testing.T) {
	t.Run("with config URL has text and resource link", func(t *testing.T) {
		configURL := "https://grafana.example.com/connections/datasources/new"
		result := credentialViolationResult("some_reason", configURL)

		assert.True(t, result.IsError)
		require.Len(t, result.Content, 2)

		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))
		assert.Equal(t, "credential_policy_redirect", payload["outcome"])
		assert.Equal(t, "some_reason", payload["reason"])
		assert.Equal(t, configURL, payload["open_config_page_url"])

		link, ok := result.Content[1].(mcp.ResourceLink)
		require.True(t, ok)
		assert.Equal(t, configURL, link.URI)
	})

	t.Run("without config URL has text only", func(t *testing.T) {
		result := credentialViolationResult("some_reason", "")

		assert.True(t, result.IsError)
		require.Len(t, result.Content, 1)
		_, ok := result.Content[0].(mcp.TextContent)
		assert.True(t, ok)
	})

	t.Run("config_page_opened is false when browser cannot be opened", func(t *testing.T) {
		// In a headless test environment the browser open will fail, so
		// config_page_opened must be false (not absent) so the LLM knows to
		// tell the user to navigate manually rather than saying the page was opened.
		configURL := "https://grafana.example.com/connections/datasources/new"
		result := credentialViolationResult("some_reason", configURL)

		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))
		_, exists := payload["config_page_opened"]
		assert.True(t, exists, "config_page_opened must always be present in the payload")
	})
}

// ---- credentialCreatedWithRedirectResult ----

func TestCredentialCreatedWithRedirectResult(t *testing.T) {
	t.Run("not an error since datasource was created", func(t *testing.T) {
		result := credentialCreatedWithRedirectResult(
			&CreateDatasourceResult{UID: "abc"},
			"secure_json_data_found",
			"https://grafana.example.com/connections/datasources/edit/abc",
		)
		assert.False(t, result.IsError)
	})

	t.Run("with config URL has text and resource link", func(t *testing.T) {
		configURL := "https://grafana.example.com/connections/datasources/edit/abc-123"
		result := credentialCreatedWithRedirectResult(
			&CreateDatasourceResult{ID: 42, UID: "abc-123", Name: "My DS"},
			"secure_json_data_found",
			configURL,
		)

		require.Len(t, result.Content, 2)

		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))
		assert.Equal(t, "created_without_credentials", payload["outcome"])
		assert.Equal(t, "secure_json_data_found", payload["reason"])
		assert.Equal(t, configURL, payload["configure_credentials_url"])

		link, ok := result.Content[1].(mcp.ResourceLink)
		require.True(t, ok)
		assert.Equal(t, configURL, link.URI)
	})

	t.Run("without config URL has text only", func(t *testing.T) {
		result := credentialCreatedWithRedirectResult(
			&CreateDatasourceResult{UID: "abc"},
			"secure_json_data_found",
			"",
		)

		require.Len(t, result.Content, 1)
		_, ok := result.Content[0].(mcp.TextContent)
		assert.True(t, ok)
	})

	t.Run("datasource details included in payload", func(t *testing.T) {
		dsResult := &CreateDatasourceResult{ID: 99, UID: "my-uid", Name: "My Prometheus", Message: "Datasource added"}
		result := credentialCreatedWithRedirectResult(
			dsResult,
			"basic_auth_user_via_mcp_disallowed",
			"https://grafana.example.com/connections/datasources/edit/my-uid",
		)

		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))

		ds, ok := payload["datasource"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "my-uid", ds["uid"])
		assert.Equal(t, "My Prometheus", ds["name"])
	})

	t.Run("config_page_opened present when config URL provided", func(t *testing.T) {
		configURL := "https://grafana.example.com/connections/datasources/edit/abc"
		result := credentialCreatedWithRedirectResult(
			&CreateDatasourceResult{UID: "abc"},
			"secure_json_data_found",
			configURL,
		)

		text, ok := result.Content[0].(mcp.TextContent)
		require.True(t, ok)
		var payload map[string]any
		require.NoError(t, json.Unmarshal([]byte(text.Text), &payload))
		_, exists := payload["config_page_opened"]
		assert.True(t, exists, "config_page_opened must be present when a URL is provided")
	})
}
