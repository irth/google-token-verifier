package googleVerifier

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

// Verifier is used for veryfing Google's JSON Web Tokens.
type Verifier struct {
	ClientID string
	Keys     map[string]string
}

// FetchKeys retrieves Google's keys from their API.
func (v *Verifier) FetchKeys() error {
	r, err := http.Get("https://www.googleapis.com/oauth2/v1/certs")
	if err != nil {
		return errors.Wrap(err, "couldn't fetch the keys")
	}
	err = json.NewDecoder(r.Body).Decode(&v.Keys)
	if err != nil {
		return errors.Wrap(err, "couldn't decode the keys")
	}
	return nil
}

// GoogleAuthTokenClaim contains the data from Google's JWT.
// See the Valid field to see if it's valid.
type GoogleAuthTokenClaim struct {
	jwt.StandardClaims
	Name *string `json:"name,omitempty"`
}

// ErrTokenInvalid is an error returned when the token couldn't be verified
type ErrTokenInvalid struct {
	Reason       string
	WrappedError error
}

func (t ErrTokenInvalid) Error() string {
	if len(t.Reason) > 0 {
		return fmt.Sprintf("Token invalid: %s", t.Reason)
	}

	if t.WrappedError != nil {
		return fmt.Sprintf("Token invalid: %s", t.WrappedError.Error())
	}

	return "Token invalid."
}

// Cause returns the underlying cause of the error, if possible.
func (t ErrTokenInvalid) Cause() error {
	return t.WrappedError
}

// Verify checks if the token is trusted and correct.
func (v Verifier) Verify(tokenString string) (*GoogleAuthTokenClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &GoogleAuthTokenClaim{}, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"].(string)
		if key, ok := v.Keys[kid]; ok {
			rsa, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key))
			if err != nil {
				return nil, errors.Wrapf(err, "Couldn't parse the public key %s.", kid)
			}
			return rsa, nil
		}

		return nil, fmt.Errorf("Key %s not found", kid)
	})

	if err != nil {
		return nil, ErrTokenInvalid{
			WrappedError: err,
		}
	}

	if !token.Valid {
		return nil, ErrTokenInvalid{}
	}

	claim := token.Claims.(*GoogleAuthTokenClaim)

	if !claim.VerifyAudience(v.ClientID, true) {
		return nil, ErrTokenInvalid{
			Reason: "Client ID doesn't match",
		}
	}

	return claim, nil
}
