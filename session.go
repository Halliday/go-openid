package openid

import (
	"strings"
	"time"
)

type Session struct {
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
