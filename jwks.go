package openid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type plainJWK struct {
	KeyId   string `json:"kid"`
	KeyType string `json:"kty"`
	Alg     string `json:"alg"`
	Use     string `json:"use"`

	// alg=EC (Elliptic Curve Keys)
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`

	// alg=RSA (RSA Keys)
	N string `json:"n"`
	E string `json:"e"`

	K string `json:"k"`
}

type JWK struct {
	Algorithm interface{}
	Use       string
	KeyId     string
}

func (jwk *JWK) UnmarshalJSON(b []byte) error {
	var plain plainJWK
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	jwk.KeyId = plain.KeyId
	jwk.Use = plain.Use

	switch plain.KeyType {
	case "EC":
		if plain.X == "" || plain.Y == "" || plain.Crv == "" {
			return e("invalid_jwk")
		}

		xCoordinate, err := base64urlTrailingPadding(plain.X)
		if err != nil {
			return err
		}
		yCoordinate, err := base64urlTrailingPadding(plain.Y)
		if err != nil {
			return err
		}

		algo := new(ecdsa.PublicKey)
		switch plain.Crv {
		case "P-256":
			algo.Curve = elliptic.P256()
		case "P-384":
			algo.Curve = elliptic.P384()
		case "P-521":
			algo.Curve = elliptic.P521()
		}

		algo.X = big.NewInt(0).SetBytes(xCoordinate)
		algo.Y = big.NewInt(0).SetBytes(yCoordinate)
		jwk.Algorithm = algo
		return nil

	case "OKP":
		if plain.X == "" {
			return e("invalid_jwk")
		}

		bytes, err := base64urlTrailingPadding(plain.X)
		if err != nil {
			return err
		}

		algo := new(ed25519.PublicKey)
		*algo = bytes
		jwk.Algorithm = algo
		return nil

	case "oct":
		if plain.K == "" {
			return e("invalid_jwk")
		}
		bytes, err := base64urlTrailingPadding(plain.K)
		if err != nil {
			return err
		}
		jwk.Algorithm = bytes
		return nil

	case "RSA":
		if plain.E == "" || plain.N == "" {
			return e("invalid_jwk")
		}

		e, err := base64.RawURLEncoding.DecodeString(plain.E)
		if err != nil {
			return err
		}
		n, err := base64.RawURLEncoding.DecodeString(plain.N)
		if err != nil {
			return err
		}

		algo := new(rsa.PublicKey)
		algo.E = int(big.NewInt(0).SetBytes(e).Uint64())
		algo.N = big.NewInt(0).SetBytes(n)
		jwk.Algorithm = algo
		return nil

	default:
		return e("unknown_jwk_kty", "kty", plain.KeyType)
	}
}

type KeySet map[string]*JWK

func (set KeySet) Keyfunc(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, e("no_kid")
	}
	key := set[kid]
	if key == nil {
		return nil, e("kid_not_found")
	}
	return key.Algorithm, nil
}

func GetKeySet(url string) (set KeySet, err error) {

	var jwks struct {
		Keys []*JWK
	}

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		return nil, e("jwks_content_type", "ContentType", contentType)
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}
	set = make(KeySet, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key != nil {
			set[key.KeyId] = key
		}
	}
	return set, nil
}

////////////////////////////////////////////////////////////////////////////////

// base64urlTrailingPadding removes trailing padding before decoding a string from base64url. Some non-RFC compliant
// JWKS contain padding at the end values for base64url encoded public keys.
//
// Trailing padding is required to be removed from base64url encoded keys.
// RFC 7517 defines base64url the same as RFC 7515 Section 2:
// https://datatracker.ietf.org/doc/html/rfc7517#section-1.1
// https://datatracker.ietf.org/doc/html/rfc7515#section-2
func base64urlTrailingPadding(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}
