package gauth

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var (
	recovChars = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RequiredEmail(fID string, data map[string]interface{}) error {
	s, _ := data[fID].(string)
	_, err := mail.ParseAddress(s)
	if err != nil {
		return errors.New("enter a valid email")
	}
	return nil
}

func RequiredText(fID string, data map[string]interface{}) error {
	s, _ := data[fID].(string)
	if len(s) > 100 {
		return errors.New("too long")
	}
	if len(s) == 0 {
		return errors.New("required")
	}
	return nil
}

func RequiredPassword(fID string, data map[string]interface{}) error {
	s, _ := data[fID].(string)
	if s == "" {
		return errors.New("required")
	}
	var (
		hasMinLen  = false
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)
	if len(s) >= 7 {
		hasMinLen = true
	}
	for _, char := range s {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	if !hasMinLen {
		return errors.New("must be 7 characters")
	}
	if !hasUpper {
		return errors.New("must have upper case")
	}
	if !hasLower {
		return errors.New("must have lower case")
	}
	if !hasNumber {
		return errors.New("must have number")
	}
	if !hasSpecial {
		return errors.New("must have special characters")
	}
	return nil
}

func AuthFromContext(ctx context.Context) *Auth {
	if auth, ok := ctx.Value(AuthKey).(*Auth); ok {
		return auth
	}
	return nil
}

func hashPassword(password string, cost int) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func validPassword(hashed, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil
}

func randomJWTKey() ([]byte, error) {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func validRecaptcha(secret string, response string, ip string) error {
	type verify struct {
		Success bool `json:"success"`
	}
	hc := &http.Client{}
	resp, err := hc.PostForm("https://www.google.com/recaptcha/api/siteverify", url.Values{
		"secret":   {secret},
		"response": {response},
		"remoteip": {ip},
	})

	if err != nil {
		return fmt.Errorf("validRecaptcha: PostForm error %v", err)
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var v verify
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	if !v.Success {
		return errors.New("failed recaptcha")
	}
	return nil
}

func realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Appengine-User-Ip"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ", ")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	ra, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ra
}

func unverifiedClaims(t string) (jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(t, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("unverifiedClaims: parse error %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}
	return nil, errors.New("invalid claims")
}

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = recovChars[rand.Intn(len(recovChars))]
	}
	return string(b)
}

// sha1(ip+userAgent+key+$salt) + $salt
func clientFromRequest(r *http.Request, key, salt string) string {
	if salt == "" {
		salt = fmt.Sprintf("$%d", time.Now().Unix())
	}
	cid := realIP(r) + r.Header.Get("User-Agent") + key + salt
	h := sha1.New()
	h.Write([]byte(cid))
	return hex.EncodeToString(h.Sum(nil)) + salt
}
