package email

import "context"

type (
	// Update email templates by implementing these interface in your IdentityProvider.
	// You can use {link} and {fieldID} for any variables.

	// To allow email notification you must implement your account provider to also be an email sender
	Sender interface {
		SendEmail(ctx context.Context, toEmail string, subject string, textBody string, htmlBody string) error
	}

	EmailBaseURL interface {
		EmailBaseURL(ctx context.Context) string
	}

	ConfirmEmail interface {
		ConfirmEmail(ctx context.Context) (subject string, parts []Part)
	}

	UpdateEmail interface {
		UpdateEmail(ctx context.Context) (subject string, parts []Part)
	}

	ResetPassword interface {
		ResetPassword(ctx context.Context) (subject string, parts []Part)
	}

	LoginEmail interface {
		LoginEmail(ctx context.Context) (subject string, parts []Part)
	}
)
