package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/julienschmidt/httprouter"
)

var loginCallbackTemplate = template.Must(template.New("").Parse(`<html>
<head></head>
<body>
<h1>Client Login Callback</h1>
<script>
window.onload = function() {
	window.location.replace("{{ .RedirectURI }} ");
}
</script>
</html>`))

func handleLoginCallback(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if len(r.URL.Query().Get("error")) > 0 {
		handleError(w, fmt.Errorf("%s \n %s", r.URL.Query().Get("error_description"), r.URL.Query().Get("error_hint")))
		return
	}

	//todo check state

	code := r.URL.Query().Get("code")
	conf := getOAuth2Conf()
	token, err := conf.Exchange(Ctx, code)
	if err != nil {
		handleError(w, err)
		return
	}

	idt := token.Extra("id_token")
	fmt.Printf("Access Token:\n\t%s\n", token.AccessToken)
	fmt.Printf("Refresh Token:\n\t%s\n", token.RefreshToken)
	fmt.Printf("Expires in:\n\t%s\n", token.Expiry.Format(time.RFC1123))
	fmt.Printf("ID Token:\n\t%v\n\n", idt)

	http.SetCookie(w, &http.Cookie{
		Name:  "accessToken",
		Value: token.AccessToken,
	})

	http.SetCookie(w, &http.Cookie{
		Name:  "idToken",
		Value: fmt.Sprintf("%v", idt),
	})

	state := &State{}
	stateJson := r.URL.Query().Get("state")
	err = json.Unmarshal([]byte(stateJson), state)

	if err != nil {
		handleError(w, err)
		return
	}

	_ = loginCallbackTemplate.Execute(w, struct {
		RedirectURI string
	}{
		RedirectURI: state.RedirectURL,
	})
}
