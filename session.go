package caddyoidc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"golang.org/x/oauth2"
)

type Session struct {
	Sign     []byte                 `json:"sign"`
	Token    *oauth2.Token          `json:"token"`
	UserInfo map[string]interface{} `json:"user_info"`
	Claims   map[string]interface{} `json:"claims"`
}

func (s *Session) Values() map[string]interface{} {
	values := map[string]interface{}{}
	for name, value := range s.UserInfo {
		values["oidc.userinfo."+name] = value
	}
	for name, value := range s.Claims {
		values["oidc.claim."+name] = value
	}
	buf := new(bytes.Buffer)
	json.NewEncoder(buf).Encode(s.UserInfo)
	values["oidc.userinfo"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	buf.Reset()
	json.NewEncoder(buf).Encode(s.Claims)
	values["oidc.claims"] = base64.StdEncoding.EncodeToString(buf.Bytes())
	values["oidc.authorization"] = s.Token.Type() + " " + s.Token.AccessToken
	return values
}
