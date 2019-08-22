package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/go-acme/lego/v3/registration"
)

type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func NewUser(email string) *User {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &User{Email: email, key: privateKey}
}
