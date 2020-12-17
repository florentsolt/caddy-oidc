package caddyoidc

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

type App struct {
	providers map[string]*Provider
	ctx       caddy.Context
	log       *zap.Logger
	mux       sync.RWMutex
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "oidc",
		New: func() caddy.Module { return new(App) },
	}
}

func (app *App) Provision(ctx caddy.Context) error {
	app.ctx = ctx
	app.log = ctx.Logger(app)
	app.providers = map[string]*Provider{}
	return nil
}

func (app *App) Start() error {
	// check for userinfo to refresh in a go routine
	return nil
}

func (app *App) Stop() error {
	return nil
}

func (app *App) RegisterProvider(provider *Provider) string {
	app.mux.Lock()
	defer app.mux.Unlock()

	h := sha1.New()
	io.WriteString(h, provider.ClientID)
	io.WriteString(h, provider.ClientSecret)
	io.WriteString(h, provider.URL)
	id := string(h.Sum(nil))

	app.providers[id] = provider
	app.log.Info("provider registered", zap.Any("config", provider))

	return fmt.Sprintf("%x", id)
}

func (app *App) GetSession(r *http.Request) *Session {
	app.mux.RLock()
	defer app.mux.RUnlock()
	for _, provider := range app.providers {
		if session := provider.GetSession(r); session != nil {
			return session
		}
	}
	return nil
}

var (
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
