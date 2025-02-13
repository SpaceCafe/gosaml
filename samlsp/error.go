package samlsp

import (
	"errors"
	"log"
	"net/http"

	"github.com/crewjam/saml"
)

// ErrorFunction is a callback that is invoked to return an error to the
// web user.
type ErrorFunction func(w http.ResponseWriter, r *http.Request, err error)

// DefaultOnError is the default ErrorFunction implementation. It prints
// a message via the standard log package and returns a simple text
// "Forbidden" message to the user.
func DefaultOnError(w http.ResponseWriter, _ *http.Request, err error) {
	var samlInvalidResponseError *saml.InvalidResponseError
	if errors.As(err, &samlInvalidResponseError) {
		log.Printf("WARNING: received invalid saml response: %s (now: %s) %s",
			samlInvalidResponseError.Response, samlInvalidResponseError.Now, samlInvalidResponseError.PrivateErr)
	} else {
		log.Printf("ERROR: %s", err)
	}
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}
