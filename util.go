package gauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/mail"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RequiredEmail(fID string, data map[string]string) error {
	s := data[fID]
	_, err := mail.ParseAddress(s)
	if err != nil {
		return errors.New("enter a valid email")
	}
	return nil
}

func RequiredText(fID string, data map[string]string) error {
	s := data[fID]
	if len(s) > 100 {
		return errors.New("too long")
	}
	if len(s) == 0 {
		return errors.New("required")
	}
	return nil
}

func RequiredPassword(fID string, data map[string]string) error {
	s := data[fID]
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

func structToMap(src interface{}) (map[string]interface{}, error) {
	dst := new(map[string]interface{})
	b, err := json.Marshal(src)
	if err != nil {
		return nil, fmt.Errorf("structToMap json.Marshal error %v", err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return nil, fmt.Errorf("structToMap json.Unmarshal error %v", err)
	}
	return *dst, nil
}
