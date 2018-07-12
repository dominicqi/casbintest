package main

import (
	"github.com/casbin/casbin"
	"github.com/labstack/gommon/log"
	"github.com/alexedwards/scs/engine/memstore"
	"github.com/alexedwards/scs/session"
	"time"
	"dominicqi.com/casbinexample/model"
	"net/http"
	"fmt"
	"dominicqi.com/casbinexample/authrozation"
)

func main() {
	e, err := casbin.NewEnforcerSafe("./config/auth_model.conf", "./config/policy.csv")
	if err != nil {
		log.Fatal(err)
	}
	engine := memstore.New(30 * time.Minute)
	sessionManager := session.Manage(engine, session.IdleTimeout(30*time.Minute), session.Persist(true), session.Secure(true))
	users := createUsers()
	mux := http.NewServeMux()
	mux.Handle("/login",loginHandler(users))
	mux.Handle("/logout",logoutHandler())
	mux.Handle("/member/current",currentMemberHandler())
	mux.Handle("/member/role",memberRoleHandler())
	mux.Handle("/admin/stuff",adminHandler())

	log.Print("server start on localhost 8080")
	log.Fatal(http.ListenAndServe(":8080",sessionManager(authrozation.Authorizer(e,users)(mux))))

}

func createUsers() model.Users {
	users := model.Users{}
	users = append(users, model.User{ID: 1, Name: "Admin", Role: "admin"})
	users = append(users, model.User{ID: 2, Name: "Sabine", Role: "member"})
	users = append(users, model.User{ID: 3, Name: "Sepp", Role: "member"})
	return users
}

func loginHandler(users model.Users)  http.HandlerFunc{
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		name := r.PostFormValue("name")
		user,err := users.FindByName(name)
		if err != nil {
			writeError(http.StatusBadRequest, "WRONG_CREDENTIALS", w, err)
			return
		}
		if err := session.RegenerateToken(r); err != nil {
			writeError(http.StatusInternalServerError, "ERROR", w, err)
			return
		}
		session.PutInt(r, "userID", user.ID)
		session.PutString(r, "role", user.Role)
		writeSuccess("SUCCESS", w)
	})
}

func logoutHandler() http.HandlerFunc  {
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		if err := session.Renew(r); err != nil {
			writeError(http.StatusInternalServerError, "ERROR", w, err)
			return
		}
	})
}

func currentMemberHandler() http.HandlerFunc  {
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		userID, err := session.GetInt(r, "userID")
		if err != nil {
			writeError(http.StatusInternalServerError, "ERROR", w, err)
			return
		}
		writeSuccess(fmt.Sprintf("current UserId %d",userID),w)
	})
}

func memberRoleHandler()  http.HandlerFunc{
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		role, err := session.GetString(r, "role")
		if err != nil {
			writeError(http.StatusInternalServerError,"ERROR",w,err)
			return
		}
		writeSuccess(fmt.Sprintf("user  role :%s",role),w)
	})
}

func adminHandler()  http.HandlerFunc{
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		writeSuccess("I AM ADMIN!",w)
	})
}

func writeError(status int,message string,w http.ResponseWriter,err error)  {
	log.Print("ERR: ",err.Error())
	w.WriteHeader(status)
	w.Write([]byte(message))
}

func writeSuccess(message string, w http.ResponseWriter)  {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(message))
}