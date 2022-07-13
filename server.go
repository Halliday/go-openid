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

type Server struct {
	Addr string

	Config *Configuration

	route           router.Route
	RefreshTokenKey []byte
	AccessTokenKey  []byte
	TokenExpiry     time.Duration

	Clients map[string]*Client

	SessionStore SessionStore
	UserStore    UserStore
}

func NewServer(addr string, sessionStore SessionStore, userStore UserStore, clients map[string]*Client, next http.Handler) *Server {
	s := &Server{
		Addr:         addr,
		SessionStore: sessionStore,
		UserStore:    userStore,
		Clients:      clients,
		TokenExpiry:  time.Minute * 10,
		Config: &Configuration{
			Issuer:                addr,
			AuthorizationEndpoint: addr + "login",
			TokenEndpoint:         addr + "token",
		},
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
			// "userinfo": &router.Route{
			// 	Paths: map[string]http.Handler{
			// 		"picture": &router.Route{
			// 			Methods: map[string]http.Handler{
			// 				http.MethodPost: http.HandlerFunc(s.servePostUserinfoPicture),
			// 			},
			// 		},
			// 	},
			// },
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

func (s *Server) getClient(clientId string) *Client {
	return s.Clients[clientId]
}

func (s *Server) serveToken(resp http.ResponseWriter, req *http.Request) {
	ctx := req.Context()
	if err := req.ParseForm(); err != nil {
		tools.ServeError(resp, err)
		return
	}
	// responseType := req.Form.Get("response_type")

	// clientId := req.Form.Get("client_id")
	// client := s.getClient(clientId)
	// if client == nil {
	// 	tools.ServeError(resp, e("no_client"))
	// 	return
	// }

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

		aud, sess, err := s.ParseRefreshToken(refreshToken)
		if err != nil {
			tools.ServeError(resp, err)
			return
		}
		sub, scopes, err := s.SessionStore.RefreshSession(ctx, aud, sess)
		if err != nil {
			tools.ServeError(resp, err)
			return
		}
		accessToken, err := s.CreateAccessToken(aud, sub, scopes)
		if err != nil {
			tools.ServeError(resp, err)
			return
		}
		tools.ServeJSON(resp, TokenResponse{
			AccessToken: accessToken,
			TokenType:   "Bearer",
			ExiresIn:    int64(s.TokenExpiry / time.Second),
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

func (s *Server) userinfo(ctx context.Context) (*Userinfo, error) {
	sess := CtxSession(ctx)
	if sess == nil {
		return nil, e("unauthorized")
	}
	return s.UserStore.Userinfo(ctx, sess.Subject)
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
		aud, id, err := s.ParseRefreshToken(req.Token)
		if err != nil {
			// throw no error on invalid tokens
			// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2
			return nil
		}
		return s.SessionStore.RevokeSession(ctx, aud, id)
	}
	return e("unsupported_token_type")
}

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
	return ""
}

func (s *Server) CreateAccessToken(aud string, sub string, scopes []string) (string, error) {
	return s.CreateAccessTokenExp(aud, sub, scopes, s.TokenExpiry)
}

const AccessTokenSubjectPrefix = "user|"

func (s *Server) CreateAccessTokenExp(aud string, sub string, scopes []string, exp time.Duration) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud":   aud,
		"iss":   s.Addr,
		"sub":   AccessTokenSubjectPrefix + sub,
		"scope": strings.Join(scopes, " "),
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(exp).Unix(),
	})
	return accessToken.SignedString(s.AccessTokenKey)
}

var noTime time.Time

func (s *Server) ParseAccessToken(accessToken string) (aud string, sub string, scopes []string, iat time.Time, exp time.Time, err error) {
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.AccessTokenKey, nil
	})
	if err != nil {
		switch er := err.(type) {
		case *jwt.ValidationError:
			if er.Errors&jwt.ValidationErrorExpired != 0 {
				return "", "", nil, noTime, noTime, e("token_expired")
			}
		}
		return "", "", nil, noTime, noTime, err
	}
	claims := token.Claims.(jwt.MapClaims)
	aud = claims["aud"].(string)

	sub, ok := claims["sub"].(string)
	if !ok || !strings.HasPrefix(sub, AccessTokenSubjectPrefix) {
		return "", "", nil, noTime, noTime, fmt.Errorf("bad accessToken claims: bad subject")
	}
	sub = sub[len(AccessTokenSubjectPrefix):]
	scopesStr := claims["scope"].(string)
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, " ")
	}
	iat = time.Unix(int64(claims["iat"].(float64)), 0)
	exp = time.Unix(int64(claims["exp"].(float64)), 0)
	return aud, sub, scopes, iat, exp, nil
}

const RefreshTokenSubjectPrefix = "session|"

func (s *Server) CreateRefreshToken(aud string, sess string) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"aud": aud,
		"iss": s.Addr,
		"iat": time.Now().Unix(),
		"sub": RefreshTokenSubjectPrefix + sess,
	})
	return refreshToken.SignedString(s.RefreshTokenKey)
}

func (s *Server) ParseRefreshToken(refreshToken string) (aud string, sess string, err error) {
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.RefreshTokenKey, nil
	})
	if err != nil {
		return "", "", err
	}
	claims := token.Claims.(jwt.MapClaims)
	aud, _ = claims["aud"].(string)
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss != s.Addr {
		return "", "", e("issuer")
	}
	if !strings.HasPrefix(sub, RefreshTokenSubjectPrefix) {
		return "", "", e("session_sub")
	}
	sub = sub[len(RefreshTokenSubjectPrefix):]
	return aud, sub, err
}

func (s *Server) createIdToken(aud string, none string, u *Userinfo) (string, error) {
	claims := IdTokenClaims{
		Audience: aud,
		Userinfo: *u,
		Nonce:    none,
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	return idToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
}

type TokenRequest struct {
	Subject string `json:"-"`

	ClientId     string
	ResponseType string
	Scope        string
	// State        string
	// RedirectUri  string
	Nonce string
}

// type AuthorizationRequest struct {
// 	ClientId string `json:"client_id"`
// 	TokenRequest
// 	State       string `json:"state"`
// 	RedirectUri string `json:"redirect_uri"`
// }

type TokenResponse struct {
	// for ResponseType = code
	Code string `json:"code"`

	// for ResponseType = token
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExiresIn     int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`

	// for ReponseType = id_token
	IdToken string `json:"id_token,omitempty"`
}

func (s *Server) Authorize(ctx context.Context, req *TokenRequest) (resp *TokenResponse, err error) {
	sub := req.Subject
	responseTypes := strings.Split(req.ResponseType, " ")
	scopes := NewScopes(req.Scope)
	resp = new(TokenResponse)

	if stringSliceIncludes(responseTypes, "token") {
		sess, err := s.SessionStore.CreateSession(ctx, req.ClientId, sub, scopes)
		if err != nil {
			return nil, err
		}
		accessToken, err := s.CreateAccessToken(req.ClientId, sub, scopes)
		if err != nil {
			return nil, err
		}
		refreshToken, err := s.CreateRefreshToken(req.ClientId, sess)
		if err != nil {
			return nil, err
		}
		resp.Scope = scopes.String()
		resp.AccessToken = accessToken
		resp.RefreshToken = refreshToken
		resp.TokenType = "Bearer"
		resp.ExiresIn = int64(s.TokenExpiry / time.Second)
	}

	if stringSliceIncludes(responseTypes, "id_token") && scopes.Has("openid") {
		userinfo, err := s.UserStore.Userinfo(ctx, sub)
		if err != nil {
			return nil, err
		}
		idToken, err := s.createIdToken(sub, req.Nonce, userinfo)
		if err != nil {
			return nil, err
		}
		resp.IdToken = idToken
	}

	return resp, nil
}

// func (r TokenRequest) Values() url.Values {
// 	v := make(url.Values)
// 	v.Set("client_id", r.ClientId)
// 	v.Set("response_type", r.ResponseType)
// 	v.Set("redirect_uri", r.RedirectUri)
// 	if r.Scope != "" {
// 		v.Set("scope", r.Scope)
// 	}
// 	if r.State != "" {
// 		v.Set("state", r.State)
// 	}
// 	if r.Nonce != "" {
// 		v.Set("nonce", r.Nonce)
// 	}
// 	return v
// }

// func (r TokenResponse) Values() url.Values {
// 	v := make(url.Values)
// 	v.Set("access_token", r.AccessToken)
// 	v.Set("token_type", r.TokenType)
// 	v.Set("exires_in", strconv.FormatInt(r.ExiresIn, 10))
// 	if r.RefreshToken != "" {
// 		v.Set("refresh_token", r.RefreshToken)
// 	}
// 	if r.Scope != "" {
// 		v.Set("scope", r.Scope)
// 	}
// 	if r.State != "" {
// 		v.Set("state", r.State)
// 	}
// 	return v
// }

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

////////////////////////////////////////////////////////////////////////////////

// type AuthorizationRequest struct {
// 	Subject string
// 	TokenRequest
// 	State string
// }

// func (req *AuthorizationRequest) DecodeValues(v url.Values) {
// 	req.Subject = v.Get("sub")
// 	req.ResponseType = v.Get("response_type")
// 	req.Scope = v.Get("scope")
// 	req.Nonce = v.Get("nonce")
// 	req.State = v.Get("state")
// }

// type AuthorizationResponse struct {
// 	Code string `json:"code,omitempty"`
// 	TokenResponse
// 	State string `json:"state,omitempty"`
// }

// func (resp AuthorizationResponse) EncodeValues() url.Values {
// 	v := make(url.Values)
// 	if resp.State != "" {
// 		v.Set("state", resp.State)
// 	}
// 	if resp.AccessToken != "" {
// 		v.Set("access_token", resp.AccessToken)
// 		v.Set("expires_in", strconv.FormatInt(resp.ExiresIn, 10))
// 		v.Set("scope", resp.Scope)
// 		v.Set("token_type", resp.TokenType)
// 		if resp.RefreshToken != "" {
// 			v.Set("refresh_token", resp.RefreshToken)
// 		}
// 	}
// 	if resp.IdToken != "" {
// 		v.Set("id_token", resp.IdToken)
// 	}
// 	return v
// }
