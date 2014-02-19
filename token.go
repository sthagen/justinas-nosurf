package nosurf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
)

const (
	tokenLength = 32
)

/*
There are two types of tokens.

* The unencrypted "real" token consists of 32 random bytes.
  It is stored in a cookie (base64-encoded) and it's the
  "reference" value that sent tokens get compared to.

* The encrypted "sent" token consists of 64 bytes:
  32 byte key used for one-time pad encryption and
  32 byte "real" token encrypted with the said key.
  It is used as a value (base64-encoded as well)
  in forms and/or headers.

Upon processing, both tokens are base64-decoded
and then treated as 32/64 byte slices.
*/

// A token is generated by returning tokenLength bytes
// from crypto/rand
func generateToken() []byte {
	bytes := make([]byte, tokenLength)
	_, _ = io.ReadFull(rand.Reader, bytes)

	// I'm not sure how to handle the error from the above call.
	// It shouldn't EVER really happen,
	// as we check for the availablity of crypto/random
	// in the init() function
	// and both /dev/urandom and CryptGenRandom()
	// should be inexhaustible.

	return bytes
}

func b64encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func b64decode(data string) []byte {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	return decoded
}

// Verifies the sent token equals the real one
// and returns a bool value indicating if tokens are equal.
// Supports encrypted tokens.
func verifyToken(realToken, sentToken []byte) bool {
	realN := len(realToken)
	sentN := len(sentToken)

	// sentN == tokenLength means the token is unencrypted
	// sentN == 2*tokenLength means the token is encrypted

	if realN == tokenLength && sentN == 2*tokenLength {
		return verifyEncrypted(realToken, sentToken)
	} else {
		return false
	}
}

// Verifies the encrypted token
func verifyEncrypted(realToken, sentToken []byte) bool {
	sentPlain := decryptToken(sentToken)
	return subtle.ConstantTimeCompare(realToken, sentPlain) == 1
}

func init() {
	// Check that cryptographically secure PRNG is available
	// In case it's not, panic.
	buf := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, buf)

	if err != nil {
		panic(fmt.Sprintf("crypto/rand is unavailable: Read() failed with %#v", err))
	}
}