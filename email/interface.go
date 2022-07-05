package email

import "context"

type (
	// Update email templates by implementing these interface in your AccountProvider.
	// You can use {link} and {fieldID} for any variables.

	// To allow email notification you must implement your account provider to also be an email sender
	Sender interface {
		SendEmail(ctx context.Context, toEmail string, subject string, textBody string, htmlBody string) error
	}

	ConfirmEmail interface {
		ConfirmEmail() (subject string, parts []Part)
	}

	ResetPassword interface {
		ResetPassword() (subject string, parts []Part)
	}
)
