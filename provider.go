package caddyoidc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(Provider{})
	httpcaddyfile.RegisterHandlerDirective("oidc", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		provider := new(Provider)
		err := provider.UnmarshalCaddyfile(h.Dispenser)
		return provider, err
	})
}

type Endpoints struct {
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	UserInfo      string `json:"userinfo_endpoint"`
	Revocation    string `json:"revocation_endpoint"`
	EndSession    string `json:"end_session_endpoint"` // post_logout_redirect_uri
}

type Provider struct {
	ClientID            string    `json:"client_id"`
	ClientSecret        string    `json:"client_secret"`
	Scopes              []string  `json:"scopes"`
	Endpoints           Endpoints `json:"endpoints"`
	URL                 string    `json:"provider"`
	CookiePath          string    `json:"cookie_path"`
	CookieNameKey       string    `json:"cookie_name_key"`
	CookieNameProvider  string    `json:"cookie_name_provider"`
	CookieNameState     string    `json:"cookie_name_state"`
	CookieNameRedirect  string    `json:"cookie_name_redirect"`
	LoginPath           string    `json:"login_path"`
	LogoutPath          string    `json:"logout_path"`
	CallbackPath        string    `json:"callback_path"`
	LogoutRedirect      string    `json:"logout_redirect"`
	DefaultRoot         string    `json:"default_root"`
	LazyLoad            bool      `json:"lazy_load"`
	RemoteConfigTimeout string    `json:"remote_config_timeout"`

	logger      *zap.Logger
	oAuthConfig *oauth2.Config
	sessions    map[string]*Session
	mux         sync.RWMutex
	id          string
}

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oidc",
		New: func() caddy.Module { return new(Provider) },
	}
}

var ErrUnableToGetProviderConfig = errors.New("Unable to get provider config")

const ProviderUrlSuffix = "/.well-known/openid-configuration"

func (provider *Provider) LoadRemoteConfig() error {
	provider.mux.Lock()
	defer provider.mux.Unlock()

	url := provider.URL
	if !strings.HasSuffix(url, ProviderUrlSuffix) {
		url = strings.TrimSuffix(url, "/")
		url += ProviderUrlSuffix
	}
	provider.logger.Info("loading remote config", zap.String("url", url))

	client := new(http.Client)
	duration, err := time.ParseDuration(provider.RemoteConfigTimeout)
	if err != nil {
		provider.logger.Error("unable to parse duration", zap.String("duration", provider.RemoteConfigTimeout), zap.Error(err))
		duration = time.Second * 5
	}
	client.Timeout = duration
	res, err := client.Get(url)
	if err != nil {
		provider.logger.Error(ErrUnableToGetProviderConfig.Error(), zap.Error(err))
		return ErrUnableToGetProviderConfig
	}
	if res.StatusCode != 200 {
		provider.logger.Error(ErrUnableToGetProviderConfig.Error(), zap.Int("status", res.StatusCode))
		return ErrUnableToGetProviderConfig
	}
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(&provider.Endpoints); err != nil {
		provider.logger.Error(ErrUnableToGetProviderConfig.Error(), zap.Error(err))
		return ErrUnableToGetProviderConfig
	}
	if provider.Endpoints.Authorization == "" || provider.Endpoints.Token == "" ||
		provider.Endpoints.UserInfo == "" {
		provider.logger.Error(ErrUnableToGetProviderConfig.Error(), zap.Any("endpoints", provider.Endpoints))
		return ErrUnableToGetProviderConfig
	}
	provider.oAuthConfig = &oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Scopes:       provider.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   provider.Endpoints.Authorization,
			TokenURL:  provider.Endpoints.Token,
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	provider.LazyLoad = false
	return nil
}

func (provider *Provider) Provision(ctx caddy.Context) error {
	provider.logger = ctx.Logger(provider)
	provider.sessions = map[string]*Session{}

	if provider.LoginPath == "" {
		provider.LoginPath = "{http.request.uri.path.dir}login"
	}
	if provider.LogoutPath == "" {
		provider.LogoutPath = "{http.request.uri.path.dir}logout"
	}
	if provider.CallbackPath == "" {
		provider.CallbackPath = "{http.request.uri.path.dir}callback"
	}
	if provider.LogoutRedirect == "" {
		provider.LogoutRedirect = "{http.request.scheme}://{http.request.hostport}{http.request.uri.path.dir}login"
	}
	if provider.DefaultRoot == "" {
		provider.DefaultRoot = "{http.request.scheme}://{http.request.hostport}"
	}
	if provider.CookiePath == "" {
		provider.CookiePath = "/"
	}
	if provider.CookieNameKey == "" {
		provider.CookieNameKey = "_key"
	}
	if provider.CookieNameProvider == "" {
		provider.CookieNameProvider = "_provider"
	}
	if provider.CookieNameState == "" {
		provider.CookieNameState = "_state"
	}
	if provider.CookieNameRedirect == "" {
		provider.CookieNameRedirect = "_redirect"
	}

	if provider.RemoteConfigTimeout == "" {
		provider.RemoteConfigTimeout = "5s"
	}
	if !provider.LazyLoad {
		if err := provider.LoadRemoteConfig(); err != nil {
			provider.logger.Error("Unable to load remote config", zap.Error(err))
			return err
		}
	}

	if app, err := ctx.App("oidc"); err != nil {
		return err
	} else if app, ok := app.(*App); !ok {
		return errors.New("Unable to get oidc app")
	} else {
		provider.id = app.RegisterProvider(provider)
	}

	return nil
}

func (provider *Provider) Validate() error {
	return nil
}

func (provider *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if len(d.RemainingArgs()) > 0 {
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			switch d.Val() {

			case "client_id":
				if !d.Args(&provider.ClientID) {
					return d.ArgErr()
				}
			case "client_secret":
				if !d.Args(&provider.ClientSecret) {
					return d.ArgErr()
				}
			case "scopes":
				provider.Scopes = d.RemainingArgs()
				if len(provider.Scopes) == 0 {
					return d.ArgErr()
				}
			case "provider":
				if !d.Args(&provider.URL) {
					return d.ArgErr()
				}
			case "login_path":
				if !d.Args(&provider.LoginPath) {
					return d.ArgErr()
				}
			case "logout_path":
				if !d.Args(&provider.LogoutPath) {
					return d.ArgErr()
				}
			case "callback_path":
				if !d.Args(&provider.CallbackPath) {
					return d.ArgErr()
				}
			case "logout_redirect":
				if !d.Args(&provider.LogoutRedirect) {
					return d.ArgErr()
				}
			case "default_root":
				if !d.Args(&provider.DefaultRoot) {
					return d.ArgErr()
				}
			case "cookie_path":
				if !d.Args(&provider.CookiePath) {
					return d.ArgErr()
				}
			case "cookie_name_key":
				if !d.Args(&provider.CookieNameKey) {
					return d.ArgErr()
				}
			case "cookie_name_provider":
				if !d.Args(&provider.CookieNameProvider) {
					return d.ArgErr()
				}
			case "cookie_name_state":
				if !d.Args(&provider.CookieNameState) {
					return d.ArgErr()
				}
			case "cookie_name_redirect":
				if !d.Args(&provider.CookieNameRedirect) {
					return d.ArgErr()
				}
			case "lazy_load":
				provider.LazyLoad = true

			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

func (provider *Provider) RandString() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func (provider *Provider) Sign(r *http.Request) ([]byte, error) {
	h := sha1.New()
	io.WriteString(h, r.Header.Get("User-Agent"))
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, errors.New("unable to parse host:port from RemoteAddr")
	}
	if _, err := io.WriteString(h, ip); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func (provider *Provider) RefreshUserInfo(session *Session) error {
	client := provider.oAuthConfig.Client(context.TODO(), session.Token)
	resp, err := client.Get(provider.Endpoints.UserInfo)
	if err != nil || resp == nil {
		provider.logger.Error("unable to get user info", zap.Error(err))
		return errors.New("unable to get user info")
	}
	if resp.StatusCode != 200 {
		provider.logger.Error("unable to get user info", zap.Int("status", resp.StatusCode))
		return errors.New("unable to get user info")
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&session.UserInfo); err != nil {
		return errors.New("unable to decode user info")
	}
	return nil
}

func (provider *Provider) RegisterSession(r *http.Request, token *oauth2.Token) (string, error) {
	sign, err := provider.Sign(r)
	if err != nil {
		provider.logger.Error("unable to sign request", zap.Error(err))
		return "", err
	}
	session := &Session{
		Sign:  sign,
		Token: token,
	}
	if err := provider.RefreshUserInfo(session); err != nil {
		provider.logger.Error("unable to refresh user info", zap.Error(err))
		return "", err
	}
	provider.logger.Info("login", zap.Any("userinfo", session.UserInfo))

	var key string
	provider.mux.Lock()
	for {
		key = provider.RandString()
		if _, exists := provider.sessions[key]; exists {
			continue
		}
		provider.sessions[key] = session
		break
	}
	provider.mux.Unlock()
	return key, nil
}

func (provider *Provider) GetSession(r *http.Request) *Session {
	if provider.LazyLoad {
		if err := provider.LoadRemoteConfig(); err != nil {
			provider.logger.Error("unable to load remote config", zap.Error(err))
			return nil
		}
	}

	if r.Header.Get("Authorization") != "" {
		split := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		token := &oauth2.Token{
			AccessToken: split[1],
			TokenType:   split[0],
		}
		session := &Session{
			Token: token,
		}
		provider.logger.Info("Authorization", zap.Any("token", token))

		if err := provider.RefreshUserInfo(session); err != nil {
			provider.logger.Error("unable to refresh user info", zap.Error(err))
			return nil
		}
		return session
	}

	id, err := r.Cookie(provider.CookieNameProvider)
	if err != nil || id == nil || id.Value == "" {
		return nil
	}
	if provider.id != id.Value {
		return nil
	}

	key, err := r.Cookie(provider.CookieNameKey)
	if err != nil || key == nil || key.Value == "" {
		return nil
	}
	provider.mux.RLock()
	session, exists := provider.sessions[key.Value]
	provider.mux.RUnlock()

	if !exists {
		return nil
	}
	if sign, err := provider.Sign(r); err != nil {
		return nil
	} else if !bytes.Equal(sign, session.Sign) {
		return nil
	}
	return session
}

func (provider *Provider) Callback(w http.ResponseWriter, r *http.Request) error {
	state, err := r.Cookie(provider.CookieNameState)
	if err != nil {
		provider.logger.Error("unable to find state", zap.Error(err))
		w.WriteHeader(http.StatusForbidden)
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:   provider.CookieNameState,
		Path:   provider.CookiePath,
		Value:  "",
		MaxAge: -1,
	})

	if r.FormValue("state") != state.Value {
		provider.logger.Error("Invalid oauth state")
		return errors.New("Invalid oauth state")
	}

	token, err := provider.oAuthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		provider.logger.Error("unable to exchange", zap.Error(err))
		return err
	}
	key, err := provider.RegisterSession(r, token)
	if err != nil {
		provider.logger.Error("unable to register session", zap.Error(err))
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:  provider.CookieNameKey,
		Path:  provider.CookiePath,
		Value: key,
	})
	http.SetCookie(w, &http.Cookie{
		Name:  provider.CookieNameProvider,
		Path:  provider.CookiePath,
		Value: provider.id,
	})

	url, err := r.Cookie(provider.CookieNameRedirect)
	if err != nil {
		provider.logger.Error("unable to find redirect url", zap.Error(err))
		w.WriteHeader(http.StatusForbidden)
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:   provider.CookieNameRedirect,
		Path:   provider.CookiePath,
		Value:  "",
		MaxAge: -1,
	})

	http.Redirect(w, r, url.Value, http.StatusTemporaryRedirect)
	w.WriteHeader(200)
	return nil
}

func (provider *Provider) Login(w http.ResponseWriter, r *http.Request) error {
	session := provider.GetSession(r)
	if session != nil {
		return nil
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	expiration := time.Now().Add(20 * time.Minute)
	state := provider.RandString()
	http.SetCookie(w, &http.Cookie{
		Name:    provider.CookieNameState,
		Path:    provider.CookiePath,
		Value:   state,
		Expires: expiration,
	})

	redirect := ""
	q := r.URL.Query()
	if q.Get("redirect") != "" {
		redirect = q.Get("redirect")
	} else if r.Referer() != "" {
		redirect = r.Referer()
	} else {
		redirect = repl.ReplaceKnown(provider.DefaultRoot, "")
	}
	http.SetCookie(w, &http.Cookie{
		Name:    provider.CookieNameRedirect,
		Path:    provider.CookiePath,
		Value:   redirect,
		Expires: expiration,
	})
	provider.oAuthConfig.RedirectURL = repl.ReplaceKnown(
		provider.DefaultRoot+provider.CallbackPath, "")
	u := provider.oAuthConfig.AuthCodeURL(state)
	http.Redirect(w, r, u, http.StatusTemporaryRedirect)
	return nil
}

func (provider *Provider) Logout(w http.ResponseWriter, r *http.Request) error {
	key, err := r.Cookie(provider.CookieNameKey)
	if err != nil || key == nil || key.Value == "" {
		return provider.Login(w, r)
	}
	provider.mux.Lock()
	delete(provider.sessions, key.Value)
	provider.mux.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:   provider.CookieNameKey,
		Path:   provider.CookiePath,
		Value:  "",
		MaxAge: -1,
	})

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	if provider.Endpoints.EndSession != "" {
		u, err := url.Parse(provider.Endpoints.EndSession)
		if err != nil {
			provider.logger.Error("unable to parse end session url", zap.Error(err))
			return err
		}
		q := u.Query()
		q.Add("post_logout_redirect_uri", repl.ReplaceKnown(provider.LogoutRedirect, ""))
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
		return nil
	}

	http.Redirect(w, r, repl.ReplaceKnown(provider.LogoutRedirect, ""), http.StatusTemporaryRedirect)
	return nil
}

func (provider *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	if provider.LazyLoad {
		if err := provider.LoadRemoteConfig(); err != nil {
			provider.logger.Error("unable to load remote config", zap.Error(err))
			return err
		}
	}

	switch r.URL.Path {
	case repl.ReplaceKnown(provider.LoginPath, ""):
		return provider.Login(w, r)
	case repl.ReplaceKnown(provider.LogoutPath, ""):
		return provider.Logout(w, r)
	case repl.ReplaceKnown(provider.CallbackPath, ""):
		return provider.Callback(w, r)
	default:
		return next.ServeHTTP(w, r)
	}
}

var (
	_ caddy.Provisioner           = (*Provider)(nil)
	_ caddy.Validator             = (*Provider)(nil)
	_ caddyhttp.MiddlewareHandler = (*Provider)(nil)
	_ caddyfile.Unmarshaler       = (*Provider)(nil)
)
