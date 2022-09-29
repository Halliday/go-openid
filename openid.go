package openid

import (
	"context"
	_ "embed"

	"github.com/halliday/go-module"
)

//go:embed messages.csv
var messages string

var _, e, Module = module.New("openid", messages)

var ErrNoUser = e("no_user")
var ErrEmailAlreadyRegistered = e("email_already_registered")
var ErrInvalidCredentials = e("invalid_credentials")

type UserStore interface {
	Userinfo(ctx context.Context, sub string) (*Userinfo, error)
}

type SessionStore interface {
	RefreshSession(ctx context.Context, aud string, id string, newScopes []string) (sub string, grantedScopes []string, err error)
	CreateSession(ctx context.Context, aud string, sub string, scopes []string) (id string, grantedScopes []string, err error)
	RevokeSession(ctx context.Context, aud string, id string) (err error)
}

const OpenIdScope = "openid"
