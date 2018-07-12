package model

import "fmt"

type User struct {
	ID   int
	Name string
	Role string
}

type Users []User

func (u Users) Exists(id int) bool {
	for _, user := range u {
		if user.ID == id {
			return true
		}
	}
	return false
}

func (u Users) FindByName(name string) (us User,err error) {
	for _, user := range u {
		if user.Name == name {
			return user,nil
		}
	}
	return User{},fmt.Errorf("not found user :%s",name)
}
