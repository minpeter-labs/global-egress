package zenproxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestHandler_retries_anonymous_free_request_when_exit_is_rate_limited(t *testing.T) {
	// Given
	var policies []string
	var authorizations []string
	var bodies []string
	attempt := 0
	handler, err := newWithTransportFactory(Options{Attempts: 3}, func(policy string) http.RoundTripper {
		policies = append(policies, policy)
		return roundTripFunc(func(request *http.Request) (*http.Response, error) {
			attempt++
			authorizations = append(authorizations, request.Header.Get("Authorization"))
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Fatalf("read outbound body: %v", readErr)
			}
			bodies = append(bodies, string(body))
			if attempt == 1 {
				return response(http.StatusTooManyRequests, `{"error":{"type":"FreeUsageLimitError"}}`), nil
			}
			return response(http.StatusOK, `{"choices":[{"message":{"content":"OK"}}]}`), nil
		})
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	requestBody := []byte(`{"model":"deepseek-v4-flash-free","messages":[{"role":"user","content":"hi"}]}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer workspace-key-must-not-leave")
	recorder := httptest.NewRecorder()

	// When
	handler.ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if attempt != 2 {
		t.Fatalf("attempts = %d, want 2", attempt)
	}
	for index, authorization := range authorizations {
		if authorization != "" {
			t.Fatalf("attempt %d forwarded Authorization %q", index+1, authorization)
		}
	}
	if len(bodies) != 2 || bodies[0] != string(requestBody) || bodies[1] != string(requestBody) {
		t.Fatalf("request body was not replayed exactly: %#v", bodies)
	}
	if len(policies) != 2 || policies[0] != policies[1] {
		t.Fatalf("retry attempts did not share one unique-IP batch: %#v", policies)
	}
	if !strings.HasPrefix(policies[0], "any=1;uniq=zen-") {
		t.Fatalf("policy = %q, want anonymous unique-IP rotation policy", policies[0])
	}
}

func TestHandler_replaces_blocked_client_user_agent(t *testing.T) {
	// Given
	var outboundUserAgent string
	handler, err := newWithTransportFactory(Options{Attempts: 1}, func(string) http.RoundTripper {
		return roundTripFunc(func(request *http.Request) (*http.Response, error) {
			outboundUserAgent = request.Header.Get("User-Agent")
			return response(http.StatusOK, `{"choices":[]}`), nil
		})
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/chat/completions",
		strings.NewReader(`{"model":"deepseek-v4-flash-free","messages":[]}`),
	)
	request.Header.Set("User-Agent", "Python-urllib/3.13")
	recorder := httptest.NewRecorder()

	// When
	handler.ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if outboundUserAgent != "global-egress-zen-public/1.0" {
		t.Fatalf("outbound User-Agent = %q", outboundUserAgent)
	}
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
