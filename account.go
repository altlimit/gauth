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
		account, err := ga.AccountProvider.IdentityLoad(ctx, auth.UID)
		if err != nil {
			ga.internalError(w, err)
			return
		}
		data := ga.loadIdentity(account)
		delFields := []string{ga.PasswordFieldID, FieldActiveID, FieldRecoveryCodesID, FieldTOTPSecretID}
		skipFields := make(map[string]bool)
		for _, v := range delFields {
			skipFields[v] = true
		}
		skipFields[FieldCodeID] = true
		skipFields[ga.EmailFieldID] = true
		cleanAccount := func() {
			totpEnabled, okT := data[FieldTOTPSecretID].(string)
			recovEnabled, okR := data[FieldRecoveryCodesID].(string)
			for _, v := range delFields {
				delete(data, v)
			}
			if okT && len(totpEnabled) > 0 {
				data[FieldTOTPSecretID] = true
			}
			if okR && len(recovEnabled) > 0 {
				data[FieldRecoveryCodesID] = len(strings.Split(recovEnabled, "|"))
			}
		}
		switch r.Method {
		case http.MethodGet:
			cleanAccount()
			ga.writeJSON(http.StatusOK, w, data)
			return
		case http.MethodPost:
			req := make(map[string]interface{})
			if err := ga.bind(r, &req); err != nil {
				ga.badError(w, err)
				return
			}
			fieldsByID := make(map[string]*form.Field)
			var valFields []*form.Field
			pw, _ := req[ga.PasswordFieldID].(string)
			for _, f := range fields {
				fieldsByID[f.ID] = f
				// only validate fields that are present
				if val, ok := req[f.ID]; ok {
					valFields = append(valFields, f)

					if _, ok := skipFields[f.ID]; !ok {
						data[f.ID] = val
					}
				}
			}
			vErrs := ga.validateFields(valFields, req)
			if len(vErrs) > 0 {
				ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: vErrs})
				return
			}

			if pw != "" {
				data[ga.PasswordFieldID], err = hashPassword(pw, ga.BCryptCost)
				if err != nil {
					ga.internalError(w, err)
					return
				}
			}
			if recovery, ok := req[FieldRecoveryCodesID].(string); ok && len(recovery) > 0 {
				var codes []string
				for _, val := range strings.Split(recovery, "|") {
					code, err := hashPassword(val, ga.BCryptCost)
					if err != nil {
						ga.internalError(w, err)
						return
					}
					codes = append(codes, code)
				}
				data[FieldRecoveryCodesID] = strings.Join(codes, "|")
			}
			secret, _ := req[FieldTOTPSecretID].(string)
			if secret == "0" {
				data[FieldTOTPSecretID] = ""
			} else if code, ok := req[FieldCodeID].(string); ok && len(code) > 0 {
				if secret != "" {
					if !totp.Validate(code, secret) {
						ga.validationError(w, FieldCodeID, "invalid")
						return
					}
					data[FieldTOTPSecretID] = secret
				}
			}

			status := http.StatusOK
			nEmail, _ := req[ga.EmailFieldID].(string)
			oEmail, _ := data[ga.EmailFieldID].(string)
			if nEmail != oEmail {
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

			_, err = ga.saveIdentity(ctx, account, data)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			cleanAccount()
			ga.writeJSON(status, w, data)
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
