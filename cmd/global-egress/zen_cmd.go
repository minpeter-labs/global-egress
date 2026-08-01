package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/minpeter/global-egress/internal/zenproxy"
)

func runZenPublic(ctx context.Context, args []string) error {
	fs := newFlagSet("zen-public")
	listenAddress := fs.String("listen", "127.0.0.1:8090", "HTTP listen address")
	forwardProxy := fs.String("forward-proxy", "http://127.0.0.1:3128", "global-egress HTTP proxy URL")
	passwordFile := fs.String("proxy-password-file", "", "file containing the global-egress proxy password")
	attempts := fs.Int("attempts", 8, "maximum distinct egress attempts per request")
	if err := fs.Parse(args); err != nil {
		return err
	}

	password, err := readZenProxyPassword(*passwordFile)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	handler, err := zenproxy.New(zenproxy.Options{
		ForwardProxy:  *forwardProxy,
		ProxyPassword: password,
		Attempts:      *attempts,
		Logger:        logger,
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		return fmt.Errorf("listen Zen public gateway: %w", err)
	}
	logger.Info("Zen public gateway listening", slog.String("address", listener.Addr().String()))

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Debug("Zen public gateway shutdown", slog.String("error_type", fmt.Sprintf("%T", err)))
		}
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve Zen public gateway: %w", err)
	}
	return nil
}

func readZenProxyPassword(path string) (string, error) {
	if path == "" {
		return "", errors.New("zen-public: -proxy-password-file is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("zen-public: read proxy password: %w", err)
	}
	password := strings.TrimSpace(string(raw))
	if password == "" {
		return "", errors.New("zen-public: proxy password is empty")
	}
	return password, nil
}
