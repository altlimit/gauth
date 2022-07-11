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

		if claims["act"] == actionVerify && len(claims["sub"]) > 0 {
			data, err := ga.AccountProvider.IdentityLoad(ctx, claims["sub"])
			if err == ErrAccountNotFound {
				ga.writeJSON(http.StatusNotFound, w, errorResponse{Error: "account not found"})
				return
			}
			if err == ErrAccountNotActive {
				data[FieldActiveID] = "1"
				if err := ga.AccountProvider.IdentitySave(ctx, data); err != nil {
					ga.internalError(w, err)
					return
				}
			}
			ga.writeJSON(http.StatusOK, w, "OK")
		}
		return
	}
}
