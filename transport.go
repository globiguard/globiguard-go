package globiguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type QueryValue any

type Transport struct {
	BaseURL     string
	ClientName  string
	Credential  Credential
	Environment Environment
	HTTPClient  *http.Client
}

var reservedHeaders = map[string]struct{}{
	"x-globiguard-client":          {},
	"x-globiguard-environment":     {},
	"x-globiguard-project-id":      {},
	"x-globiguard-publishable-key": {},
	"x-globiguard-secret-key":      {},
	"x-globiguard-local-mode":      {},
	"x-globiguard-local-token":     {},
}

func AssertServiceURL(serviceName, serviceURL string, environment Environment, requireLocalHost bool) error {
	parsed, err := url.Parse(serviceURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return &ConfigError{Message: serviceName + " service URL must be a valid URL."}
	}
	if environment != EnvironmentLocal && parsed.Scheme != "https" {
		return &ConfigError{Message: serviceName + " service URL must use HTTPS outside the local environment."}
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return &ConfigError{Message: serviceName + " service URL must be a service origin, not a versioned API path."}
	}
	if requireLocalHost {
		host := parsed.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" && !strings.HasSuffix(host, ".localhost") {
			return &ConfigError{Message: serviceName + " service URL must use a localhost or loopback host with local credentials."}
		}
	}
	return nil
}

func EncodePathSegment(value string) string {
	return url.PathEscape(value)
}

func JoinURL(baseURL, path string) (string, error) {
	if strings.Contains(path, "://") || strings.HasPrefix(path, "//") {
		return "", &ConfigError{Message: "Request paths must be relative to the configured GlobiGuard service."}
	}
	if !strings.HasPrefix(path, "/") {
		return "", &ConfigError{Message: "Request paths must start with '/'."}
	}
	if strings.Contains(path, "?") || strings.Contains(path, "#") {
		return "", &ConfigError{Message: "Request paths must not include query strings or fragments."}
	}
	if strings.Contains(path, "\\") {
		return "", &ConfigError{Message: "Request paths must not contain backslashes."}
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", &ConfigError{Message: "Configured GlobiGuard service URL is invalid."}
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	cleanSegments := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		decoded, err := url.PathUnescape(segment)
		if err != nil {
			return "", &ConfigError{Message: "Request paths must contain valid percent-encoding."}
		}
		if decoded == "." || decoded == ".." {
			return "", &ConfigError{Message: "Request paths must not contain dot segments."}
		}
		cleanSegments = append(cleanSegments, segment)
	}
	base.Path = "/" + strings.Join(cleanSegments, "/")
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func (t Transport) Request(ctx context.Context, path string, method string, query map[string]QueryValue, body any, headers map[string]string, out any) error {
	requestURL, err := JoinURL(t.BaseURL, path)
	if err != nil {
		return err
	}
	parsed, err := url.Parse(requestURL)
	if err != nil {
		return &ConfigError{Message: "Resolved request URL is invalid."}
	}
	values := parsed.Query()
	for key, value := range query {
		if value != nil {
			values.Set(key, stringifyQuery(value))
		}
	}
	parsed.RawQuery = values.Encode()

	var reader io.Reader
	requestHeaders := t.buildHeaders(headers)
	if body != nil {
		switch value := body.(type) {
		case []byte:
			reader = bytes.NewReader(value)
		case string:
			reader = strings.NewReader(value)
		default:
			payload, err := json.Marshal(value)
			if err != nil {
				return err
			}
			reader = bytes.NewReader(payload)
			if requestHeaders.Get("content-type") == "" {
				requestHeaders.Set("content-type", "application/json")
			}
		}
	}
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, parsed.String(), reader)
	if err != nil {
		return err
	}
	req.Header = requestHeaders
	client := t.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	decoded, err := decodeResponse(resp.Header.Get("content-type"), responseBody)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Status: resp.StatusCode, Body: decoded}
	}
	if out != nil && decoded != nil {
		payload, err := json.Marshal(decoded)
		if err != nil {
			return err
		}
		return json.Unmarshal(payload, out)
	}
	return nil
}

func (t Transport) buildHeaders(headers map[string]string) http.Header {
	result := http.Header{}
	if t.Credential.ProjectID != "" {
		result.Set("x-globiguard-project-id", t.Credential.ProjectID)
	}
	switch t.Credential.Kind {
	case CredentialPublishable:
		result.Set("x-globiguard-publishable-key", t.Credential.Token)
	case CredentialSecret:
		result.Set("x-globiguard-secret-key", t.Credential.Token)
	case CredentialLocal:
		result.Set("x-globiguard-local-mode", "true")
		if t.Credential.Token != "" {
			result.Set("x-globiguard-local-token", t.Credential.Token)
		}
	}
	for key, value := range headers {
		if _, ok := reservedHeaders[strings.ToLower(key)]; !ok {
			result.Set(key, value)
		}
	}
	result.Set("x-globiguard-client", t.ClientName)
	result.Set("x-globiguard-environment", string(t.Environment))
	return result
}

func stringifyQuery(value QueryValue) string {
	switch v := value.(type) {
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	default:
		return fmt.Sprint(v)
	}
}

func decodeResponse(contentType string, body []byte) (any, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if strings.Contains(contentType, "application/json") {
		var value any
		if err := json.Unmarshal(body, &value); err != nil {
			return nil, err
		}
		return value, nil
	}
	return string(body), nil
}
