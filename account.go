package gauth

import (
	"net/http"

	"github.com/altlimit/gauth/form"
)

func (ga *GAuth) accountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		fc := ga.formConfig()
		fc.Fields = append(fc.Fields, ga.fieldByID(ga.IdentityFieldID))
		// todo magic login link
		if ga.PasswordFieldID != "" {
			fc.Fields = append(fc.Fields, ga.fieldByID(ga.PasswordFieldID))
		}
		if err := form.Render(w, "account", fc); err != nil {
			ga.internalError(w, err)
		}
		return
	}
	if r.Method != http.MethodPost {
		ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
		return
	}
	var req map[string]string
	if err := ga.bind(r, &req); err != nil {
		ga.internalError(w, err)
		return
	}
	ctx := r.Context()
	if vTok, ok := req["verify"]; ok {
		claims, err := ga.tokenClaims(vTok)
		if err != nil {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
			return
		}
		uid := claims["uid"]
		if claims["act"] == actionVerify && len(uid) > 0 {
			data, err := ga.AccountProvider.IdentityLoad(ctx, uid)
			if err == ErrAccountNotFound {
				ga.writeJSON(http.StatusNotFound, w, errorResponse{Error: "account not found"})
				return
			}
			if data[FieldActiveID] != "1" {
				data[FieldActiveID] = "1"
				if _, err := ga.AccountProvider.IdentitySave(ctx, uid, data); err != nil {
					ga.internalError(w, err)
					return
				}
				ga.writeJSON(http.StatusOK, w, "OK")
				return
			}
		}
		ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "token has expired"})
		return
	}
}
