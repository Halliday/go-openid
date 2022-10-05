package openid

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/halliday/go-router"
	"github.com/halliday/go-rpc"
	"github.com/halliday/go-tools"
)

const Issuer = "iss"
const NotBefore = "nbf"
const Audience = "aud"
const Subject = "sub"
const ExpiresAt = "exp"
const IssuedAt = "iat"
const AccessTokenSubjectPrefix = "user|"
const RefreshTokenSubjectPrefix = "session|"

type Server struct {
	Addr string

	Config *Configuration

	route           router.Route
	RefreshTokenKey []byte
	TokenKey        []byte
	TokenExpiry     time.Duration

	// Clients map[string]*Client

	SessionStore SessionStore
	UserStore    UserStore

	GrantScopes func(ctx context.Context, aud string, sub string, scopes []string) (grantedScopes []string, err error)
}

func GrantScopes(ctx context.Context, aud string, sub string, scopes []string) (grantedScopes []string, err error) {
	if Scopes(scopes).Has("openid") {
		if len(scopes) == 1 {
			return scopes, nil
		}
		return []string{"openid"}, nil
	}
	return nil, nil
}

func NewServer(addr string, sessionStore SessionStore, userStore UserStore, next http.Handler) *Server {
	s := &Server{
		Addr: addr,

		SessionStore: sessionStore,
		UserStore:    userStore,
		TokenExpiry:  time.Minute * 10,

		Config: &Configuration{
			Issuer:                addr,
			AuthorizationEndpoint: addr + "login",
			TokenEndpoint:         addr + "token",
		},

		GrantScopes: GrantScopes,
	}

	s.route = router.Route{
		Paths: map[string]http.Handler{
			".well-known": &router.Route{
				Paths: map[string]http.Handler{
					"openid-configuration": http.HandlerFunc(s.ServeHTTOpenIdConfiguration),
				},
			},
			"token": &router.Route{
				Methods: map[string]http.Handler{
					http.MethodPost: http.HandlerFunc(s.serveToken),
				},
				Paths: map[string]http.Handler{
					"revoke": &router.Route{
						Methods: map[string]http.Handler{
							http.MethodPost: rpc.MustNew(s.revokeToken),
						},
					},
				},
			},
			"userinfo": rpc.MustNew(s.userinfo),
		},
		Next: next,
	}

	return s
}

func (s *Server) ServeHTTOpenIdConfiguration(resp http.ResponseWriter, req *http.Request) {
	tools.ServeJSON(resp, s.Config)
}

type sessionCtxKey struct{}

func (s *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {

	var accessToken string

	authorization := req.Header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") {
		accessToken = authorization[7:]
	}
	if authorization == "" {
		if strings.EqualFold(req.Header.Get("Connection"), "Upgrade") {
			accessToken = req.URL.Query().Get("access_token")
		}
	}

	if accessToken != "" {
		aud, sub, scopes, iat, exp, err := s.ParseAccessToken(accessToken)
		if err != nil {
			tools.ServeError(resp, err)
			return
		}
		sess := new(Session)
		sess.Server = s
		sess.IssuedAt = iat
		sess.ExpiresAt = exp
		sess.Aud = aud
		sess.Scopes = scopes
		sess.Subject = sub
		ctx := req.Context()
		ctx = context.WithValue(ctx, sessionCtxKey{}, sess)
		req = req.WithContext(ctx)
	}

	s.route.ServeHTTP(resp, req)
}

// func (s *Server) getClient(clientId string) *Client {
// 	return s.Clients[clientId]
// }

func (s *Server) serveToken(resp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	if err := req.ParseForm(); err != nil {
		tools.ServeError(resp, err)
		return
	}

	grantType := req.Form.Get("grant_type")

	// existingGrant := req.Form.Get("existing_grant")
	// if existingGrant != "" {
	// 	existingSession, err := s.parseRefreshToken(existingGrant)
	// 	if err != nil {
	// 		tools.ServeError(resp, err)
	// 		return
	// 	}
	// }

	switch grantType {
	case "refresh_token":
		refreshToken := req.Form.Get("refresh_token")
		var scopes []string
		if req.Form.Has("scope") {
			scopes = NewScopes(req.Form.Get("scope"))
		}
		accessToken, scopes, expiresIn, err := s.RefreshSession(ctx, refreshToken, scopes)
		if err != nil {
			tools.ServeError(resp, err)
			return
		}
		tools.ServeJSON(resp, TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExpiresIn:   expiresIn,
			Scope:       Scopes(scopes).String(),
		})
		return

	// case "password":
	// 	password := req.Form.Get("password")
	// 	username := req.Form.Get("username")
	// 	scope := req.Form.Get("scope ")
	// 	_, err := client.AuthToken(ctx, username, password, scope)
	// 	if err != nil {
	// 		tools.ServeError(resp, err)
	// 		return
	// 	}
	// 	return

	default:
		tools.ServeError(resp, e("no_grant_type"))
		return
	}
}

func (s *Server) Userinfo(ctx context.Context, accessToken string) (*Userinfo, error) {
	_, sub, scopes, _, _, err := s.ParseAccessToken(accessToken)
	if err != nil {
		return nil, err
	}
	if !Scopes(scopes).Has("openid") {
		return nil, e("missing_scope", "openid")
	}
	return s.UserStore.Userinfo(ctx, sub)

}

func (s *Server) userinfo(ctx context.Context) (*Userinfo, error) {
	sess := CtxSession(ctx)
	if sess == nil {
		return nil, e("unauthorized")
	}
	return s.UserStore.Userinfo(ctx, sess.Subject)
}

////////////////////////////////////////////////////////////////////////////////

func (s *Server) Revoke(ctx context.Context, refreshToken string) (err error) {
	_, id, err := s.ParseRefreshToken(refreshToken)
	if err != nil {
		return err
	}
	return s.SessionStore.RevokeSession(ctx, id)
}

type RevokeTokenRequest struct {
	Token         string
	TokenTypeHint string
}

func (s *Server) revokeToken(ctx context.Context, req *RevokeTokenRequest) (err error) {
	tokenType := req.TokenTypeHint
	if tokenType == "" {
		tokenType = TokenType(req.Token)
	}
	if tokenType == "refresh_token" {
		err := s.Revoke(ctx, req.Token)
		if err != nil {
			// throw no error on invalid tokens
			// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
			return nil
		}
		return nil
	}
	return e("unsupported_token_type")
}

////////////////////////////////////////////////////////////////////////////////

type tokenClaims struct {
	Subject string `json:"sub"`
}

func (claims tokenClaims) Valid() error {
	return nil
}

func TokenType(token string) string {
	parser := jwt.NewParser()
	var claims tokenClaims
	_, _, err := parser.ParseUnverified(token, &claims)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(claims.Subject, RefreshTokenSubjectPrefix) {
		return "refresh_token"
	}
	if strings.HasPrefix(claims.Subject, AccessTokenSubjectPrefix) {
		return "access_token"
	}
	return "" // unknown
}

////////////////////////////////////////////////////////////////////////////////

func (server *Server) CreateToken(claims map[string]interface{}) (string, error) {
	if aud, _ := claims[Audience].(string); aud == "" {
		panic("CreateToken: missing aud")
	}
	if sub, _ := claims[Subject].(string); sub == "" {
		panic("CreateToken: missing sub")
	}
	mapClaims := jwt.MapClaims{
		"iss": server.Addr,
		"iat": time.Now().Unix(),
	}
	for key, value := range claims {
		mapClaims[key] = value
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mapClaims)
	return token.SignedString(server.TokenKey)
}

func (server *Server) ParseToken(str string) (claims map[string]interface{}, err error) {
	claims = make(map[string]interface{})
	p := jwt.NewParser(jwt.WithoutClaimsValidation())
	_, err = p.ParseWithClaims(str, jwt.MapClaims(claims), func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, e("token_bad_alg", token.Header["alg"])
		}
		return server.TokenKey, nil
	})
	if err != nil {
		return nil, err
	}
	// claims = token.Claims.(jwt.MapClaims)
	iss, _ := claims[Issuer].(string)
	if iss != server.Addr {
		return claims, e("token_bad_iss")
	}

	if nbf, ok := claims[NotBefore].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return claims, e("token_bad_nbf")
		}
	}
	if exp, ok := claims[ExpiresAt].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return claims, e("token_bad_exp")
		}
	}
	if iat, ok := claims[IssuedAt].(float64); ok {
		if time.Now().Unix() < int64(iat) {
			return claims, e("token_bad_iat")
		}
	}

	return claims, nil
}

type AccessToken struct {
	Audience  string `json:"aud"`
	Subject   string `json:"sub"`
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"exp"`
	IssuedAt  int64  `json:"iat"`
}

func (t AccessToken) Valid() error {
	now := time.Now().Unix()
	if t.ExpiresAt < now {
		return e("token_bad_exp")
	}
	return nil
}

func (s *Server) CreateAccessToken(aud string, sub string, scopes []string) (string, error) {
	return s.CreateToken(map[string]interface{}{
		Audience:  aud,
		Subject:   AccessTokenSubjectPrefix + sub,
		"scope":   strings.Join(scopes, " "),
		ExpiresAt: time.Now().Add(s.TokenExpiry).Unix(),
	})
}

var noTime time.Time

func (s *Server) ParseAccessToken(accessToken string) (aud string, sub string, scopes []string, iat time.Time, exp time.Time, err error) {
	claims, err := s.ParseToken(accessToken)
	if err != nil {
		return "", "", nil, noTime, noTime, err
	}
	sub, ok := claims[Subject].(string)
	if !ok || !strings.HasPrefix(sub, AccessTokenSubjectPrefix) {
		return "", "", nil, noTime, noTime, fmt.Errorf("bad accessToken claims: bad subject")
	}
	sub = sub[len(AccessTokenSubjectPrefix):]

	aud = claims[Audience].(string)

	scopesStr := claims["scope"].(string)
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, " ")
	}
	iat = time.Unix(int64(claims[IssuedAt].(float64)), 0)
	exp = time.Unix(int64(claims[ExpiresAt].(float64)), 0)
	return aud, sub, scopes, iat, exp, nil
}

func (s *Server) CreateSession(ctx context.Context, aud string, sub string, scopes []string, nonce string) (refreshToken string, accessToken string, grantedScopes []string, expiresIn int64, idToken string, err error) {

	grantedScopes, err = s.GrantScopes(ctx, aud, sub, scopes)
	if err != nil {
		return "", "", nil, 0, "", err
	}

	sess, err := s.SessionStore.CreateSession(ctx, aud, sub, scopes)
	if err != nil {
		return "", "", nil, 0, "", err
	}
	accessToken, err = s.CreateAccessToken(aud, sub, grantedScopes)
	if err != nil {
		return "", "", nil, 0, "", err
	}
	refreshToken, err = s.CreateRefreshToken(aud, sess)
	if err != nil {
		return "", "", nil, 0, "", err
	}

	if Scopes(grantedScopes).Has("openid") {
		user, err := s.UserStore.Userinfo(ctx, sub)
		if err != nil {
			return "", "", nil, 0, "", err
		}
		idToken, err = s.CreateIdToken(aud, user, nonce)
		if err != nil {
			return "", "", nil, 0, "", err
		}
	}

	return refreshToken, accessToken, grantedScopes, int64(s.TokenExpiry / time.Second), idToken, nil
}

func (s *Server) RefreshSession(ctx context.Context, refreshToken string, filterScopes []string) (accessToken string, grantedScopes []string, expiresIn int64, err error) {
	aud, sess, err := s.ParseRefreshToken(refreshToken)
	if err != nil {
		return "", nil, 0, err
	}
	sub, grantedScopes, err := s.SessionStore.RefreshSession(ctx, sess, filterScopes)
	if err != nil {
		return "", nil, 0, err
	}
	accessToken, err = s.CreateAccessToken(aud, sub, grantedScopes)
	if err != nil {
		return "", nil, 0, err
	}
	return accessToken, grantedScopes, int64(s.TokenExpiry / time.Second), nil
}

////////////////////////////////////////////////////////////////////////////////

func (s *Server) CreateRefreshToken(aud string, sess string) (string, error) {
	return s.CreateToken(map[string]interface{}{
		Audience: aud,
		"sub":    RefreshTokenSubjectPrefix + sess,
	})
}

func (s *Server) ParseRefreshToken(refreshToken string) (aud string, sess string, err error) {
	claims, err := s.ParseToken(refreshToken)
	if err != nil {
		return "", "", err
	}
	aud, _ = claims[Audience].(string)
	sub, _ := claims[Subject].(string)
	if !strings.HasPrefix(sub, RefreshTokenSubjectPrefix) {
		return "", "", e("session_sub")
	}
	sub = sub[len(RefreshTokenSubjectPrefix):]
	return aud, sub, err
}

func (s *Server) CreateIdToken(aud string, u *Userinfo, nonce string) (string, error) {
	claims := IdTokenClaims{
		Issuer:   s.Addr,
		Audience: aud,
		Userinfo: *u,
		Nonce:    nonce,
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	return idToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
}

////////////////////////////////////////////////////////////////////////////////

// https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
// https://www.rfc-editor.org/rfc/rfc6749#section-4.2.1

type AuthRequest struct {
	ClientId     string
	ResponseType string // code, token, id_token
	Scope        string
	State        string
	RedirectUri  string
	Nonce        string
}

type AuthResponse struct {
	// for ReponseType = code
	Code string

	// for ReponseType = token
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// for ReponseType = id_token
	IdToken string `json:"id_token,omitempty"`

	State string `json:"state,omitempty"`
}

type TokenRequest struct {
	GrantType string `json:"grant_type"` // authorization_code, refresh_token

	// for GrantType = authorization_code
	// https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
	Code        string `json:"code"`
	RedirectUri string `json:"redirect_uri"` // must match the redirect_uri in the auth request
	ClientId    string `json:"client_id"`

	// for GrantType = refresh_token
	// https://www.rfc-editor.org/rfc/rfc6749#section-6
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`

	Nonce string `json:"nonce"`
}

type TokenResponse struct {
	// for ResponseType = token
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// for ReponseType = id_token
	IdToken string `json:"id_token,omitempty"`

	State string `json:"state,omitempty"`
}

func FilterRequestedScopes(scopes []string, requestedScopes []string) []string {
	n := 0
SCOPES:
	for _, scope := range scopes {
		for _, requestedScope := range requestedScopes {
			if scope == requestedScope {
				scopes[n] = scope
				n++
				continue SCOPES
			}
		}
	}
	return scopes[:n]
}
