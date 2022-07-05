package gauth

import (
	"errors"
	"math/rand"
	"net/mail"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func RequiredEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return errors.New("enter a valid email")
	}
	return nil
}

func RequiredText(text string) error {
	if len(text) > 100 {
		return errors.New("too long")
	}
	if len(text) == 0 {
		return errors.New("required")
	}
	return nil
}

func RequiredPassword(s string) error {
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

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 13)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func randomJWTKey() ([]byte, error) {
	key := make([]byte, 64)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
