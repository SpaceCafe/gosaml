package saml

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
)

// TimeNow is a function that returns the current time. The default
// value is time.Now, but it can be replaced for testing.
var TimeNow = func() time.Time { return time.Now().UTC() }

// Clock is assigned to dsig validation and signing contexts if it is
// not nil, otherwise the default clock is used.
var Clock *dsig.Clock

// RandReader is the io.Reader that produces cryptographically random
// bytes when they are need by the library. The default value is
// rand.Reader, but it can be replaced for testing.
var RandReader = rand.Reader

//nolint:unparam // This always receives 20, but we want the option to do more or less if needed.
func randomBytes(n int) []byte {
	rv := make([]byte, n)

	if _, err := io.ReadFull(RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}

func parseQuery(query string) (params map[string]string, err error) {
	params = make(map[string]string)
	for query != "" {
		var key string
		key, query, _ = strings.Cut(query, "&")
		if strings.Contains(key, ";") {
			err = fmt.Errorf("invalid semicolon separator in query")
			continue
		}
		if key == "" {
			continue
		}
		key, value, _ := strings.Cut(key, "=")
		key, err1 := url.QueryUnescape(key)
		if err1 != nil {
			if err == nil {
				err = err1
			}
			continue
		}
		params[key] = value
	}
	return params, err
}
