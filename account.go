package gauth

import (
	"net/http"
	"strings"

	"github.com/altlimit/gauth/form"
	"github.com/pquerna/otp/totp"
)

func (ga *GAuth) accountHandler(w http.ResponseWriter, r *http.Request) {
	fc := ga.formConfig()
	tabs, fields := ga.accountFields()
	tab := r.URL.Query().Get("tab")
	if tab == "" && len(tabs) > 0 {
		tab = tabs[0]
	}
	fc.Title = "Settings"
	fc.Submit = "Save"
	fc.Fields = fields
	fc.Tab = tab
	fc.Tabs = tabs

	if ga.isJson(r) {
		auth, err := ga.Authorized(ga.headerToken(r))
		if err != nil {
			ga.log("AuthorizedError: ", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: http.StatusText(http.StatusUnauthorized)})
			return
		}

		ctx := r.Context()
		acct, err := ga.AccountProvider.IdentityLoad(ctx, auth.UID)
		if err != nil {
			ga.internalError(w, err)
			return
		}

		delFields := []string{ga.PasswordFieldID, FieldActiveID, FieldRecoveryCodesID, FieldTOTPSecretID}
		skipFields := make(map[string]bool)
		for _, v := range delFields {
			skipFields[v] = true
		}
		skipFields[FieldCodeID] = true
		cleanAccount := func() {
			totpEnabled := acct[FieldTOTPSecretID] != ""
			recovEnabled := acct[FieldRecoveryCodesID] != ""
			for _, v := range delFields {
				delete(acct, v)
			}
			if totpEnabled {
				acct[FieldTOTPSecretID] = "1"
			}
			if recovEnabled {
				acct[FieldRecoveryCodesID] = "1"
			}
		}
		switch r.Method {
		case http.MethodGet:
			cleanAccount()
			ga.writeJSON(http.StatusOK, w, acct)
			return
		case http.MethodPost:
			req := make(map[string]string)
			if err := ga.bind(r, &req); err != nil {
				ga.badError(w, err)
				return
			}
			fieldsByID := make(map[string]*form.Field)
			var valFields []*form.Field
			pw := req[ga.PasswordFieldID]
			for _, f := range fields {
				fieldsByID[f.ID] = f
				// only validate fields that are present
				if val, ok := req[f.ID]; ok {
					valFields = append(valFields, f)

					if _, ok := skipFields[f.ID]; !ok {
						acct[f.ID] = val
					}
				}
			}
			vErrs := ga.validateFields(valFields, req)
			if len(vErrs) > 0 {
				ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: vErrs})
				return
			}

			if pw != "" {
				acct[ga.PasswordFieldID], err = hashPassword(pw, ga.BCryptCost)
				if err != nil {
					ga.internalError(w, err)
					return
				}
			}
			if req[FieldRecoveryCodesID] != "" {
				var codes []string
				for _, val := range strings.Split(req[FieldRecoveryCodesID], "|") {
					code, err := hashPassword(val, ga.BCryptCost)
					if err != nil {
						ga.internalError(w, err)
						return
					}
					codes = append(codes, code)
				}
				acct[FieldRecoveryCodesID] = strings.Join(codes, "|")
			}
			if req[FieldTOTPSecretID] == "0" {
				acct[FieldTOTPSecretID] = ""
			} else if code, ok := req[FieldCodeID]; ok && len(code) > 0 {
				totpSecret := req[FieldTOTPSecretID]
				if totpSecret != "" {
					if !totp.Validate(code, totpSecret) {
						ga.validationError(w, FieldCodeID, "invalid")
						return
					}
					acct[FieldTOTPSecretID] = totpSecret
				}
			}

			status := http.StatusOK
			if req[ga.EmailFieldID] != acct[ga.EmailFieldID] {
				ok, err := ga.sendMail(ctx, actionEmailUpdate, auth.UID, req)
				if err != nil {
					ga.internalError(w, err)
					return
				}
				if ok {
					// using for sent email
					status = http.StatusCreated
				}
			}

			_, err = ga.AccountProvider.IdentitySave(ctx, auth.UID, acct)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			cleanAccount()
			ga.writeJSON(status, w, acct)
			return
		}

		ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
		return
	}

	if r.Method == http.MethodGet {
		if err := form.Render(w, fc); err != nil {
			ga.internalError(w, err)
		}
		return
	}

	ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
}
