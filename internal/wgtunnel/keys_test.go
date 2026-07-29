package wgtunnel

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestDeviceLoggerRedactsFormattedNetworkDetails(t *testing.T) {
	var output bytes.Buffer
	logger := newDeviceLogger(slog.New(slog.NewTextHandler(&output, nil)), "slot-1")

	logger.Verbosef("peer endpoint %s", "203.0.113.4:51820")
	logger.Errorf("send to %s failed", "198.51.100.8:51820")

	for _, raw := range []string{"203.0.113.4", "198.51.100.8"} {
		if strings.Contains(output.String(), raw) {
			t.Fatalf("wireguard log leaked %q: %s", raw, output.String())
		}
	}
}
