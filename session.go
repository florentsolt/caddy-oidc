package caddyoidc

import (
	"context"

	"golang.org/x/oauth2"
)

type Session struct {
	Sign     []byte
	Token    *oauth2.Token
	UserInfo map[string]interface{}
}

func (s *Session) RefreshToken(config *oauth2.Config) error {
	source := config.TokenSource(context.TODO(), s.Token)
	token, err := source.Token()
	if err != nil {
		return err
	}
	s.Token = token
	return nil
}

// func (s *Session) RefreshUserInfo(url string, config *oauth2.Config) error {
// 	client := config.Client(context.TODO(), s.Token)
// 	resp, err := client.Get(url)
// 	if err != nil || resp == nil {
// 		return errors.New("Unable to get user info")
// 	}
// 	if resp.StatusCode != 200 {
// 		return errors.New("Unable to get user info")
// 	}
// 	defer resp.Body.Close()
// 	if err := json.NewDecoder(resp.Body).Decode(&s.UserInfo); err != nil {
// 		return errors.New("Unable to decode user info")
// 	}
// 	return nil
// }
