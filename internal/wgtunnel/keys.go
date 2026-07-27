package wgtunnel

import (
	"encoding/base64"
	"fmt"
	"log/slog"

	"golang.zx2c4.com/wireguard/device"
)

// wgKeyLen is the size of a Curve25519 WireGuard key in bytes.
const wgKeyLen = 32

// decodeBase64Key decodes a WireGuard key and validates its length.
func decodeBase64Key(key string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	if len(raw) != wgKeyLen {
		return nil, fmt.Errorf("expected %d key bytes, got %d", wgKeyLen, len(raw))
	}
	return raw, nil
}

// newDeviceLogger adapts wireguard-go's logger to slog.
//
// wireguard-go is chatty at Verbose level (handshake, keepalive and roaming
// messages for every peer), so device logs are emitted at debug level and
// tagged with the slot they belong to.
func newDeviceLogger(logger *slog.Logger, slotID string) *device.Logger {
	scoped := logger.With(slog.String("slot", slotID), slog.String("component", "wireguard"))
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			scoped.Debug(fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...any) {
			scoped.Warn(fmt.Sprintf(format, args...))
		},
	}
}
