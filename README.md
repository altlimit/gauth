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

**Method** : `POST` or `GET` - when you have cookie enabled

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
    "error": "invalid token"
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