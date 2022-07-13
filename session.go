package openid

import (
	"strings"
	"time"
)

type Session struct {
	// Id      string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Aud       string
	Subject   string
	Scopes    []string

	Server *Server
}

func (sess *Session) HasScope(a string) bool {
	if sess == nil {
		return false
	}
	for _, b := range sess.Scopes {
		if strings.EqualFold(a, b) {
			return true
		}
	}
	return false
}

func (sess *Session) HasAnyScope(scopes ...string) bool {
	if sess == nil {
		return false
	}
	for _, a := range scopes {
		for _, b := range sess.Scopes {
			if strings.EqualFold(a, b) {
				return true
			}
		}
	}
	return false
}

func (sess *Session) HasAllScopes(scopes ...string) bool {
	if sess == nil {
		return false
	}
SCOPES:
	for _, a := range scopes {
		for _, b := range sess.Scopes {
			if strings.EqualFold(a, b) {
				continue SCOPES
			}
		}
		return false
	}
	return true
}

// func (sess *Session) SetProfilePicture(r io.Reader) error {
// 	data, err := ioutil.ReadAll(r)
// 	if err != nil {
// 		return err
// 	}
// 	cfg, err := png.DecodeConfig(bytes.NewBuffer(data))
// 	if err != nil {
// 		return err
// 	}
// 	if cfg.Width != 64 || cfg.Height != 64 {
// 		return fmt.Errorf("bad image size, expected 64x64")
// 	}
// 	filename := filepath.Join(sess.Server.PictureDir, sess.Aud, sess.Subject, "64.png")
// 	if err := os.WriteFile(filename, data, 0644); err != nil {
// 		return err
// 	}
// 	return nil
// }
