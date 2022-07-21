![Run Tests](https://github.com/altlimit/gauth/actions/workflows/run-tests.yaml/badge.svg)

# gauth

Login, registration library for go using your own models. This has a built-in UI for login, register and account pages. Optionally just use json endpoints. This is a standalone auth system that is embedded to your application.

---
* [Install](#install)
* [Features](#features)
* [Examples](#examples)
* [How To](#how-to)
* [Endpoints](#endpoints)
---

## Features

* Registration forms with customizable input, identity, email field and password fields.
* Login form with 2FA, recovery, inactive/verify email flow.
* Passwordless login / sending login email link.
* Forgot Password / Resetting password
* Account page with customizable input and tabs, allow 2FA, password update, etc.
* Customizable color scheme.

## Install

```sh
go get github.com/altlimit/gauth
```

## Examples

Refer to `cmd/memory` for a full example that stores new accounts in memory.

## How To

This library comes with a form template that you can customize the color scheme to match with your application or simply just use the json endpoints.

You must implement the `AccountProvider` interface to allow `gauth` to know how to load or save your account/user. In `IdentityLoad` it returns an `Identity` interface which usually is your user model. If you don't have one, you can make any struct that would be use to store your user properties.

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

func (ap *accountProvider) IdentityUID(ctx context.Context, id string) (string, error) {
    // The id here is whatever you provided in IdentityFieldID - this could be email or username
    // if you support email link activation(by default it's enabled or if you have EmailFieldID provided)
    // and it's not yet active you must return ErrAccountNotActive with the actual unique ID.
    if u != nil {
        if !u.Active {
            return u.ID, gauth.ErrAccountNotActive
        }
        return u.ID, nil
    }
    // if user does not exists return ErrAccountNotFound
	return "", gauth.ErrAccountNotFound
}

func (ap *accountProvider) IdentityLoad(ctx context.Context, uid string) (gauth.Identity, error) {
    // You'll get the unique id you provided in IdentityUID here in uid and you should return a Identity,
    // your user model should implement the Identity interface like above with IdentitySave.
    // If the uid is an empty string return an empty struct for your model to be created later and ErrAccountNotFound
	if uid == "" {
		return &User{}, gauth.ErrAccountNotFound
	}
    // load user and return
	return u, nil
}

// ------ You only need to provide above, everything starting here is optional --------

func (ap *accountProvider) SendEmail(ctx context.Context, toEmail, subject, textBody, htmlBody string) error {
    // to enable email sending your provider must implement email.Sender interface.
    // using smtp, sendgrid or any transactional email api here
	log.Println("ToEmail", toEmail, "\nSubject", subject, "\nTextBody: ", textBody)
	return nil
}

// Customize how refresh token is created, by default it uses sha1(ip+userAgent+passwordHash)
// so it can be invalidated by password update
func (ap *accountProvider) CreateRefreshToken(ctx context.Context, uid string) (string, error) {
	// You can generate a list of DB logins for this user ID to easily revoke/logout this token
    // then use this loginID here and return it
	return login.ID, nil
}

// Default behaviour of logout is in memory cid blacklist in an LRU memory cache with 1000 capacity.
func (ap *accountProvider) DeleteRefreshToken(ctx context.Context, uid, cid string) error {
    // This is called on logout you should revoke your cid here, load your login and delete it
    return deleteLogged(ctx, uid, cid)
}


// Implment AccessTokenProvider to customize the grants for your access token
type Permission struct {
    Owner bool    `json:"owner"`
    Roles []int64 `json:"role_ids"`
}
// Default behaviour of CreateAccessToken is it checks cid against current request cid, you can access the *http.Request
// from context under RequestKey if needed.
func (ap *accountProvider) CreateAccessToken(ctx context.Context, uid string, cid string) (interface{}, error) {
	// We return any kind of permission that this user ID have, cid here is provided also but not necessarily needed.
    // without implementing this your grants will simply be "access"
	return Permission{
		Owner: false,
		Roles: []int64{1, 2, 3},
	}, nil
}
```

Once you have those implemented, you can either wrap any logged in page with `AuthMiddleware` or manually check with `Authorized`

```go
ga := gauth.NewDefault("Example", "http://localhost:8888", &accountProvider{})
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

**Code** : `400 BAD REQUEST`

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