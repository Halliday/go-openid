package openid

type Userinfo struct {
	Subject   string `json:"sub,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`

	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	MiddleName string `json:"middle_name,omitempty"`
	Nickname   string `json:"nickname,omitempty"`

	PreferredUsername         string `json:"preferred_username,omitempty"`
	PreferredUsernameVerified bool   `json:"preferred_username_verified"`

	Profile string `json:"profile,omitempty"`
	Picture string `json:"picture,omitempty"`
	Website string `json:"website,omitempty"`

	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`

	Gender              string   `json:"gender,omitempty"`
	Birthdate           string   `json:"birthdat,omitempty"`
	Zoneinfo            string   `json:"zoneinfo,omitempty"`
	Locale              string   `json:"locale,omitempty"`
	PhoneNumber         string   `json:"phone_number,omitempty"`
	PhoneNumberVerified bool     `json:"phone_number_verified"`
	Address             *Address `json:"address,omitempty"`

	// Password              string `json:"password,omitempty"`
	// PasswordResetSentAt int64  `json:"lastPasswordResetSend,omitempty"`

	SocialProviders []*SocialProvider `json:"social_providers,omitempty"`

	UpdatedAt int64 `json:"updated_at,omitempty"`
}

type SocialProvider struct {
	Issuer  string `json:"iss"`
	Profile string `json:"profile,omitempty"`
	Picture string `json:"picture,omitempty"`
	Website string `json:"website,omitempty"`
}

type UserinfoUpdate struct {
	Subject string `json:"sub,omitempty"`

	Name       *string `json:"name"`
	GivenName  *string `json:"given_name"`
	FamilyName *string `json:"family_name"`
	MiddleName *string `json:"middle_name"`
	Nickname   *string `json:"nickname"`

	PreferredUsername *string `json:"preferred_username"`

	Email         *string `json:"email"`
	EmailVerified *bool   `json:"email_verified"`

	Gender    *string  `json:"gender"`
	Birthdate *string  `json:"birthdate"`
	Zoneinfo  *string  `json:"zoneinfo"`
	Locale    *string  `json:"locale"`
	Address   *Address `json:"address"`

	Password *string `json:"password,omitempty"`
}

type IdTokenClaims struct {
	Audience string `json:"aud"`
	Issuer   string `json:"iss"`
	Userinfo
	Nonce string `json:"nonce"`
}

func (IdTokenClaims) Valid() error {
	return nil
}

type Address struct {
	Formatted     string `json:"formatted"`
	StreetAddress string `json:"street_address"`
	Locality      string `json:"locality"`
	Region        string `json:"region"`
	PostalCode    string `json:"postal_code"`
	Country       string `json:"country"`
}

// func (s *Server) servePostUserinfoPicture(resp http.ResponseWriter, req *http.Request) {
// 	sess := CtxSession(req.Context())
// 	if sess == nil {
// 		http.Error(resp, "Unauthorized.", http.StatusUnauthorized)
// 		return
// 	}
// 	if req.ContentLength > s.MaxPictureSize {
// 		http.Error(resp, "Request entity too large.", http.StatusRequestEntityTooLarge)
// 		return
// 	}
// 	if err := sess.SetProfilePicture(req.Body); err != nil {
// 		tools.ServeError(resp, err)
// 		return
// 	}
// 	loc := path.Join("/userinfo/picture", sess.Aud, sess.Subject, "64.png")
// 	resp.Write([]byte(loc))
// }
