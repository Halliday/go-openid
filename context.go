package openid

import (
	"context"
)

func CtxSession(ctx context.Context) *Session {
	if sess := ctx.Value(sessionCtxKey{}); sess != nil {
		return sess.(*Session)
	}
	return nil
}

func HasScope(ctx context.Context, scope string) (sess *Session, err error) {
	sess = CtxSession(ctx)
	if sess == nil {
		return nil, e("unauthorized")
	}
	if !sess.HasScope(scope) {
		return sess, e("forbidden", "Scope", scope)
	}
	return sess, nil
}

func HasAnyScope(ctx context.Context, scopes ...string) (sess *Session, err error) {
	sess = CtxSession(ctx)
	if sess == nil {
		return nil, e("unauthorized")
	}
	if !sess.HasAnyScope(scopes...) {
		return sess, e("forbidden", "Scopes", scopes)
	}
	return sess, nil
}

func HasAllScopes(ctx context.Context, scopes ...string) (sess *Session, err error) {
	sess = CtxSession(ctx)
	if sess == nil {
		return nil, e("unauthorized")
	}
	if !sess.HasAllScopes(scopes...) {
		return sess, e("forbidden", "Scopes", scopes)
	}
	return sess, nil
}
