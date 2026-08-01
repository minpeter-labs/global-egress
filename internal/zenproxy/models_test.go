package zenproxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_accepts_every_public_free_model(t *testing.T) {
	for model := range freeModelNames {
		t.Run(model, func(t *testing.T) {
			// Given
			handler, err := newWithTransportFactory(
				Options{Attempts: 1},
				func(string) http.RoundTripper {
					return roundTripFunc(func(request *http.Request) (*http.Response, error) {
						if request.Header.Get("Authorization") != "" {
							t.Fatal("public request forwarded an Authorization header")
						}
						return response(http.StatusOK, `{"choices":[]}`), nil
					})
				},
			)
			if err != nil {
				t.Fatalf("new handler: %v", err)
			}
			body, err := json.Marshal(map[string]any{
				"model":    model,
				"messages": []map[string]string{{"role": "user", "content": "hi"}},
			})
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			recorder := httptest.NewRecorder()

			// When
			handler.ServeHTTP(recorder, request)

			// Then
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
			}
		})
	}
}

func TestHandler_rejects_paid_model_before_egress(t *testing.T) {
	// Given
	called := false
	handler, err := newWithTransportFactory(
		Options{Attempts: 1},
		func(string) http.RoundTripper {
			called = true
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, `{}`), nil
			})
		},
	)
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/chat/completions",
		bytes.NewBufferString(`{"model":"deepseek-v4-flash","messages":[]}`),
	)
	recorder := httptest.NewRecorder()

	// When
	handler.ServeHTTP(recorder, request)

	// Then
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
	if called {
		t.Fatal("paid model reached the egress transport")
	}
}
