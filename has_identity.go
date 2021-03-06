package caddyoidc

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(HasIdentity{})
}

type HasIdentity struct {
	app    *App
	logger *zap.Logger
}

func (HasIdentity) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.has_identity",
		New: func() caddy.Module { return new(HasIdentity) },
	}
}

func (hasIdentity *HasIdentity) Provision(ctx caddy.Context) error {
	hasIdentity.logger = ctx.Logger(hasIdentity)
	iapp, err := ctx.App("oidc")
	if err != nil {
		return err
	}
	app, ok := iapp.(*App)
	if !ok {
		return errors.New("Unable to get oidc app")
	}
	hasIdentity.app = app
	return nil
}

func (hasIdentity *HasIdentity) Validate() error {
	return nil
}

func (hasIdentity *HasIdentity) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

var reHeaderName = regexp.MustCompile(`[^\w\-_\d]+`)

func (hasIdentity *HasIdentity) Match(r *http.Request) bool {
	session, provider := hasIdentity.app.GetSession(r)
	if session == nil {
		return false
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for name, value := range session.Values() {
		repl.Set(name, value)
	}
	for name, value := range provider.Values() {
		repl.Set(name, value)
	}
	return true
}

var (
	_ caddy.Provisioner        = (*HasIdentity)(nil)
	_ caddy.Validator          = (*HasIdentity)(nil)
	_ caddyhttp.RequestMatcher = (*HasIdentity)(nil)
	_ caddyfile.Unmarshaler    = (*HasIdentity)(nil)
)
