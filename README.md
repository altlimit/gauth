![Run Tests](https://github.com/altlimit/gauth/actions/workflows/run-tests.yaml/badge.svg)

# gauth

Login, registration library for go using your own models. This has a built-in UI for login, register and account pages. Optionally just use json endpoints. This is a standalone auth system that is embedded to your application.

---
* [Install](#install)
* [Features](#features)
* [Examples](#examples)
* [How To](#how-to)
* [Custom Tokens](#custom-tokens)
* [Custom Emails](#custom-emails)
* [Endpoints](#endpoints)
---
## Install

```sh
go get github.com/altlimit/gauth
```

## Features

* Registration forms with customizable input, identity, email field and password fields.
* Login form with 2FA, recovery, inactive/verify email flow.
* Passwordless login / sending login email link.
* Forgot Password / Resetting password
* Account page with customizable input and tabs, allow 2FA, password update, etc.
* Customizable color scheme.

## Examples

Refer to `cmd/memory` for a full example that stores new accounts in memory.

## How To

This library comes with a form template that you can customize the color scheme to match with your application or simply just use the json endpoints.

You must implement the `IdentityProvider` interface to allow `gauth` to know how to load or save your account/user. In `IdentityLoad` it returns an `Identity` interface which usually is your user model. If you don't have one, you can make any struct that would be use to store your user properties.

```go

// Here we create an Identity interface by adding "gauth" tag to map in the AccountFields you provided.
type User struct {
    ID            string
    Name          string `gauth:"name"`
    Password      string `gauth:"password"`
    Email         string `gauth:"email"`
    Active        bool   `gauth:"active"` // built-in tag
    TotpSecretKey string `gauth:"totpsecret"` // built-in tag
    RecoveryCodes string `gauth:"recoverycodes"` // built-in tag
}

func (u *User) IdentitySave(ctx context.Context) (string, error) {
    // once it reaches here, it's safe to save your user and return it's unique id
	return u.ID, nil
}

type identityProvider struct {

}

func (ip *identityProvider) IdentityUID(ctx context.Context, id string) (string, error) {
    // The id here is whatever you provided in IdentityFieldID - this could be email or username
    // if you support email link activation(by default it's enabled or if you have EmailFieldID provided)
    // and it's not yet active you must return ErrIdentityNotActive with the actual unique ID.
    if u != nil {
        if !u.Active {
            return u.ID, gauth.ErrIdentityNotActive
        }
        return u.ID, nil
    }
    // if user does not exists return ErrIdentityNotFound
	return "", gauth.ErrIdentityNotFound
}

func (ip *identityProvider) IdentityLoad(ctx context.Context, uid string) (gauth.Identity, error) {
    // You'll get the unique id you provided in IdentityUID here in uid and you should return a Identity,
    // your user model should implement the Identity interface like above with IdentitySave.
    // If the uid is an empty string return an empty struct for your model to be created later and ErrIdentityNotFound
	if uid == "" {
		return &User{}, gauth.ErrIdentityNotFound
	}
    // load user and return
	return u, nil
}

```

That's all you need, everything else will be optional.

## Custom Tokens

You can customize how your refresh and access tokens are created. The default behaviour is that your refresh token will be a JWT that has a claim `cid` which is the `sha1(IP+UserAgent+PasswordHash)`. This is invalidated by updating your password or logout will add a blacklist of `cid` for the last 1000 using in memory lru cache. Then your access token makes sure your `cid` matches before it returns the default `access` as grants which is also customizable. Without changing anything it's stateless but invalidation for logout on distributed systems will not be blocked until expiration.

```go
// called when you login
func (ip *identityProvider) CreateRefreshToken(ctx context.Context, uid string) (string, error) {
    // if you need access to *http.Request it's in ctx.Value(gauth.RequestKey)
    loginID, err := newLoginForUID(ctx, uid)
	return loginID, err
}

// called when you logout
func (ip *identityProvider) DeleteRefreshToken(ctx context.Context, uid, cid string) error {
    // This is called on logout you should revoke your cid here, load your login and delete it
    return deleteLoginForUID(ctx, uid, cid)
}


// Implment AccessTokenProvider to customize the grants for your access token
type Permission struct {
    Owner bool    `json:"owner"`
    Roles []int64 `json:"role_ids"`
}

// called everytime you refresh and create access_token
func (ip *identityProvider) CreateAccessToken(ctx context.Context, uid string, cid string) (interface{}, error) {
    // check if your cid is still logged in
    if err := isUIDLoggedIn(ctx, uid, cid); err != nil {
        return nil, err
    }
    // load this users roles into your custom grants
	roles, err := loadUserRoles(ctx, uid)
	return Permission{
		Owner: false,
		Roles: []int64{1, 2, 3},
	}, nil
}
```

Once you have those implemented, you can either wrap any logged in page with `AuthMiddleware` or manually check with `Authorized`

```go
ga := gauth.NewDefault("Example", "http://localhost:8888", &identityProvider{})
http.Handle("/auth/", ga.MustInit(false))
// here your me handler must have Authorization: Bearer {accessToken} or it will return 401
http.Handle("/api/me", ga.AuthMiddleware(meHandler()))

// you could also create your own middleware and use ga.Authorized(r) to check for auth
auth, err := ga.Authorized(r)
if err != nil {
    // not authorized
    return
}
// load your user from auth.UID if needed
user := LoadYourUser(auth.UID)
// or simply load your grants
perms := &Permission{}
err = auth.Load(perms);
```

In a single page application, you can regenerate a new access token by doing a `GET` request to `/auth/refresh` by default it has a cookie in there to give you an access token when you login. You'll need to also refresh it before it expires or just make it built-in to your http client.

## Custom Emails

You can customize all emails by implementing the email interface you wish to change. You'll also need the `email.Sender` interface to actually be able to send emails.

```go
// to enable email sending your provider must implement email.Sender interface.
func (ip *identityProvider) SendEmail(ctx context.Context, toEmail, subject, textBody, htmlBody string) error {
    // using smtp, sendgrid or any transactional email api here
	log.Println("ToEmail", toEmail, "\nSubject", subject, "\nTextBody: ", textBody)
	return nil
}

// for customizing email messages

// email.Confirmemail - for verifying the email
// email.UpdateEmail - when you are updating email
// email.ResetPassword - reset link
// email.LoginEmail - login link for passwordless login

func (ip *identityProvider) ConfirmEmail() (string, []email.Part) {
    return "Verify Email", []email.Part{
		{P: "Hi {name}"},
		{P: "Please click the link below to verify"},
		{URL: "{link}", Label: "Verify"},
	}
}
```

For the actual email template you'll need to update email.Template before you do any `emailData.Parse`.

## Endpoints

Here are the default endpoints. You can change these in your config.

### Register

**URL** : `/auth/register`

**Method** : `POST` or `GET` - provides the register page

**Body**

These are customizable fields under `AccountFields`. The `IdentityFieldID` is your email and `PasswordFieldID` for your password. This endpoint is not available if you are using passwordless system(`PasswordFieldID` is empty string). Here we have additional fields in your `AccountFields` for name and you provided `Path.Terms` so an `Agree` checkbox shows up in your registration and it's required to be `true` to successfull register.

```json
{
    "email": "",
    "name": "",
    "password": "",
    "terms": true
}
```
### Success Response

**Code** : `200 OK` or `201 Created`

201 means an email verification link has been sent, otherwise it's 200.

### Error Response

**Code** : `400 Bad Request`

Field: error message will be provided on any type of errors, depending on your provided validator you'll get the same message here.

```json
{
    "error": "validation",
    "data": {
        "email": "required",
        "name": "required"
    }
}
```

### Login

**URL** : `/auth/login`

**Method** : `POST` or `GET` - provides the Login Page

**Body**

Providing a `PasswordFieldID` will allow you to login with `IdentityFieldID` and .

```json
{
    "email": "",
    "password": ""
}
```
### Success Response

**Code** : `200 OK` or `201 Created`

201 means an email verification link has been sent(if it's passwordless then it's same here), otherwise it's 200. Also a refresh token would be written in body or if you provided `RefreshTokenCookieName` it will be written in cookie under `/auth/refresh`.

```json
{
    "refresh_token": "..."
}
```

### Error Response

**Code** : `400 Bad Request`

Field: error message will be provided on any type of errors.

```json
{
    "error": "validation",
    "data": {
        "password": "invalid"
    }
}
```

### Access Token

**URL** : `/auth/refresh`

**Method** : `POST` or `GET` - when you have cookie enabled or `DELETE` - for logging out

**Body**

When doing a `POST` you need to pass in `token` with your refresh token to get a new access token.

```json
{
    "token": "..."
}
```
### Success Response

**Code** : `200 OK`

You can now use your `access_token` in `Authorization: Bearer ...` for your authorized requests.

```json
{
    "access_token": "...",
    "token_type": "Bearer",
    "expires_in": "86400",
}
```

### Error Response

**Code** : `401 Unauthorized`

```json
{
    "error": "Unauthorized"
}
```

### Account

**URL** : `/auth/account`

**Method** : `POST` or `GET` - provides the account page

**Body**

This is the same as the account page. But here you only send the fields you want updated, otherwise it would trigger the validation. Updating your `EmailFieldID` would trigger an email verification without updating current email. Clicking the email will then update your email if you are logged in.

```json
{
    "name": ""
}
```
### Success Response

**Code** : `200 OK` or `201 Created`

201 means an email verification link has been sent, otherwise it's 200.

### Error Response

**Code** : `400 Bad Request`

Field: error message will be provided on any type of errors, depending on your provided validator you'll get the same message here.

```json
{
    "error": "validation",
    "data": {
        "name": "required"
    }
}
```

### Action

**URL** : `/auth/action`

**Method** : `POST` or `GET`

**Body**

Getting a token from different actions can be used here or triggers like reset link.

* newRecovery - returns a list of 10 random recovery codes, save this under `/auth/account` field `FieldRecoveryCodesID` or `gauth:"recoverycodes"` tag.
* newTotpKey - returns a `secret` and `url` for showing a qr code, save under `/auth/account/` field `FieldTOTPSecretID` (or `gauth:"totpsecret"` tag) with `code` to enable 2FA.
* verify - requires `token` body for verifying an email.
* resetlink - requires `IdentityFieldID` for sending a reset link.
* reset - requires `PasswordFieldID` and `token` for resetting password.
* confirmemail - requires `IdentityFieldID` for resending verification link.
* emailupdate - requires `Authrozation` header and `token` body.

```json
{
    "action": "newRecovery|newTotpKey|verify|resetlink|reset|confirmemail|emailupdate",
    "token": ""
}
```
### Success Response

**Code** : `200 OK`

### Error Response

**Code** : `400 BAD REQUEST`

Field: error message will be provided on any type of errors, depending on your provided validator you'll get the same message here.

```json
{
    "error": "invalid action"
}
```