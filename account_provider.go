package gauth

import (
	"context"
	"errors"
)

type (
	// AccountProvider must be implemented to login, register, update your user
	AccountProvider interface {
		// Check if id exists return ErrAccountExists or other errors otherwise nil
		IdentityExists(ctx context.Context, id string) error
		IdentitySave(ctx context.Context, data map[string]string) error
	}
)

var (
	ErrAccountExists = errors.New("account exists")
)
