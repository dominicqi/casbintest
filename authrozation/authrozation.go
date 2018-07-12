package authrozation

import (
	"github.com/casbin/casbin"
	"dominicqi.com/casbinexample/model"
	"net/http"
	"github.com/alexedwards/scs/session"
	"log"
	"errors"
	"fmt"
	"os"
)

func Authorizer(e *casbin.Enforcer,users model.Users)  func(next http.Handler) http.Handler{
	return func(next http.Handler) http.Handler {
		fn :=func (w http.ResponseWriter,r *http.Request){
			role, err := session.GetString(r, "role")
			if err != nil {
				writeError(http.StatusInternalServerError, "ERROR", w, err)
				return
			}
			fmt.Fprintln(os.Stdout,"cookies size %d",len(r.Cookies()))
			for _, cookie := range r.Cookies() {
				fmt.Fprintln(os.Stdout,"NAME:%S,VALUE:%S",cookie.Name,cookie.Value)
			}
			if role == "" {
				role = "anonymous"
			}

			if role == "member" {
				userId, err := session.GetInt(r, "userID")
				if err != nil {
					writeError(http.StatusInternalServerError, "ERROR", w, err)
					return
				}
				exists := users.Exists(userId)
				if !exists {
					writeError(http.StatusForbidden, "FORBIDDEN", w, errors.New("user does not exist"))
					return
				}
			}
			res, err := e.EnforceSafe(role, r.URL.Path, r.Method)
			if err != nil {
				writeError(http.StatusInternalServerError, "ERROR", w, err)
				return
			}
			if res {
				next.ServeHTTP(w,r)
			} else {
				writeError(http.StatusForbidden, "FORBIDDEN", w, errors.New("unauthorized"))
				return
			}
		}
		return http.HandlerFunc(fn)
	}
}

func writeError(status int, message string, w http.ResponseWriter, err error) {
	log.Print("ERROR: ", err.Error())
	w.WriteHeader(status)
	w.Write([]byte(message))
}
