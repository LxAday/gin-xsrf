package gin_xsrf

import (
	"github.com/gin-gonic/gin"
	"math/rand"
	"time"
)

var padding = []byte{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
	'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
	'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
	'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9',
}

var (
	// TokenLength is the length of csrf token
	TokenLength = 16

	// TokenKey is the key of csrf token
	// it could be in get-query, post-form or header
	TokenKey = "X-Csrf-Token"

	// TokenCookie is the name of token cookie
	TokenCookie = "X-Csrf-Token"

	// DefaultExpire is the default expire time of cookie
	DefaultExpire = 3600 * 6

	// RandomSec is the flag which represents the random-source
	// will be changed after each period of time
	RandomSec = false

	// randSource will be changed every DefaultExpire time
	randSource = rand.New(rand.NewSource(time.Now().UnixNano()))

	// GenerateToken returns random CSRF token
	GenerateToken = func() string {
		result := make([]byte, TokenLength)
		length := len(padding)
		for i := 0; i < TokenLength; i++ {
			result[i] = padding[randSource.Intn(length)]
		}
		return string(result)
	}
	secure   = false
	httpOnly = false
)

func init() {
	if RandomSec {
		go func() {
			for {
				time.Sleep(time.Duration(DefaultExpire) * time.Second)
				randSource = rand.New(rand.NewSource(time.Now().UnixNano()))
			}
		}()
	}
}

// SetCSRFToken set CSRF token in cookie while no token in cookie now
func SetCSRFToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, e := c.Cookie(TokenCookie)
		if e != nil {
			c.SetCookie(TokenCookie, GenerateToken(), DefaultExpire, "/", "", secure, httpOnly)
		}
		c.Next()
	}
}

// XCSRF verify the token
// if not match, returns 403
func XCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookie, e := c.Cookie(TokenCookie)
		if e != nil || cookie == "" {
			c.AbortWithStatus(403)
			return
		}
		token := c.GetHeader(TokenKey)
		if token == "" {
			token = c.PostForm(TokenKey)
			if token == "" {
				token = c.Query(TokenKey)
			}
		}
		if cookie != token {
			c.AbortWithStatus(403)
			return
		}
		c.Next()
	}
}
