package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/julienschmidt/httprouter"
)

var consumerDashboardTemplate = template.Must(template.New("").Parse(`<html>
<head></head>
<body>
<h1>Welcome to consumer dashboard</h1>
<div>You are signed in and we can recognize you with the following Access token:</div>
<div>{{ .AccessToken }}</div>
<div>ID token:</div>
<div>{{ .IDToken }}</div>
<script>
window.onload = function() {
	if ({{ .GoToAuth }}) {
    	window.location.replace("{{ .AuthURL }} ");
	}
}
</script>
</html>`))

func handleConsumerDashboardGet(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	state := State{
		RedirectURL: fmt.Sprintf("http://%s:%d/consumer/dashboard", ClientID, Port),
	}

	authTokenCookie, err := r.Cookie("accessToken")
	idTokenCookie, err := r.Cookie("idToken")
	if err != nil || authTokenCookie.Value == "" {
		authURL, err := getAuthURL(
			state,
		)

		if err != nil {
			handleError(w, err)
			return
		}

		autoLoginToken := r.URL.Query().Get("altk")
		if autoLoginToken != "" {
			state.Altk = &autoLoginToken
			authURL, err := getAuthURL(
				state,
			)

			if err != nil {
				handleError(w, err)
				return
			}
			_ = consumerDashboardTemplate.Execute(w, struct {
				AccessToken string
				IDToken  string
				GoToAuth bool
				AuthURL string
			}{
				GoToAuth:  true,
				AuthURL:   authURL,
			})
			return
		}

		_ = consumerDashboardTemplate.Execute(w, struct {
			AccessToken string
			IDToken  string
			GoToAuth bool
			AuthURL string
		}{
			GoToAuth:  true,
			AuthURL:   authURL,
		})
		return
	}

	_ = consumerDashboardTemplate.Execute(w, struct {
		AccessToken string
		IDToken  string
		GoToAuth bool
		AuthURL string
	}{
		AccessToken: authTokenCookie.Value,
		IDToken: idTokenCookie.Value,
		GoToAuth:  false,
		AuthURL:   "",
	})
}
