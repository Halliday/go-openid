package openid

import (
	"context"
)

type Client struct {
	AuthToken func(ctx context.Context, username string, password string, scope string) (*Userinfo, error)
}
