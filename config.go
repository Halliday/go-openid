package openid

import (
	"encoding/json"
	"net/http"
	"strings"
)

type Configuration struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint                 string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JwksUri                                    string   `json:"jwks_uri"`
	CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpoinAuthMethodsSupported           []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestUriParameterSupported               bool     `json:"request_uri_parameter_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	TlsClientCertificateBoundAccessTokens      bool     `json:"tls_client_certificate_bound_access_tokens"`
}

func NewConfiguration(issuer string) *Configuration {
	if !strings.HasSuffix(issuer, "/") {
		issuer += "/"
	}

	return &Configuration{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      issuer + "login",
		TokenEndpoint:                              issuer + "token",
		TokenIntrospectionEndpoint:                 issuer + "token/introspect",
		UserinfoEndpoint:                           issuer + "userinfo",
		EndSessionEndpoint:                         issuer + "logout",
		JwksUri:                                    issuer + "certs",
		CheckSessionIframe:                         issuer + "login-status-iframe.html",
		GrantTypesSupported:                        []string{"implicit", "refresh_token"},
		ResponseTypesSupported:                     []string{"code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"},
		SubjectTypesSupported:                      []string{"public", "pairwise"},
		IdTokenSigningAlgValuesSupported:           []string{"RS256"},
		UserinfoSigningAlgValuesSupported:          []string{"RS256"},
		RequestObjectSigningAlgValuesSupported:     []string{"none", "RS256"},
		ResponseModesSupported:                     []string{"query", "fragment", "form_post"},
		RegistrationEndpoint:                       issuer + "clients-registrations",
		TokenEndpoinAuthMethodsSupported:           []string{"private_key_jwt", "client_secret_basic", "client_secret_post", "client_secret_jwt"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256"},
		ClaimsSupported:                            []string{"sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email"},
		ClaimTypesSupported:                        []string{"normal"},
		ClaimsParameterSupported:                   false,
		ScopesSupported:                            []string{"openid", "email", "profile", "author"},
		RequestParameterSupported:                  true,
		RequestUriParameterSupported:               true,
		CodeChallengeMethodsSupported:              []string{"plain", "S256"},
		TlsClientCertificateBoundAccessTokens:      true,
	}
}

func Discover(url string) (c *Configuration, err error) {
	resp, err := http.Get(strings.TrimSuffix(url, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, e("discover_status", "StatusCode", resp.Status)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/json" {
		return nil, e("discover_content_type", "Content-Type", contentType)
	}
	c = new(Configuration)
	err = json.NewDecoder(resp.Body).Decode(c)
	return c, err
}

func MustDiscover(url string) *Configuration {
	config, err := Discover(url)
	if err != nil {
		panic(err)
	}
	return config
}
