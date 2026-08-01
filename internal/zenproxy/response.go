package zenproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

var hopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func (h *Handler) writeResponse(
	writer http.ResponseWriter,
	response *http.Response,
	transport http.RoundTripper,
) {
	defer closeIdleConnections(transport)
	defer func() {
		if err := response.Body.Close(); err != nil {
			h.logger.Debug("close Zen response", slog.String("error_type", fmt.Sprintf("%T", err)))
		}
	}()

	copyHeaders(writer.Header(), response.Header)
	writer.WriteHeader(response.StatusCode)
	destination := io.Writer(writer)
	if strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		if flusher, ok := writer.(http.Flusher); ok {
			destination = &flushWriter{writer: writer, flusher: flusher}
		}
	}
	if _, err := io.Copy(destination, response.Body); err != nil {
		h.logger.Debug("relay Zen response", slog.String("error_type", fmt.Sprintf("%T", err)))
	}
}

type flushWriter struct {
	writer  io.Writer
	flusher http.Flusher
}

func (w *flushWriter) Write(payload []byte) (int, error) {
	written, err := w.writer.Write(payload)
	if written > 0 {
		w.flusher.Flush()
	}
	return written, err
}

func copyHeaders(destination, source http.Header) {
	for key, values := range source {
		if _, blocked := hopHeaders[http.CanonicalHeaderKey(key)]; blocked {
			continue
		}
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(payload); err != nil {
		slog.Debug("write Zen JSON response", slog.String("error_type", fmt.Sprintf("%T", err)))
	}
}
