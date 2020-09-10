package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/julienschmidt/httprouter"
	"github.com/ory/x/randx"
	"golang.org/x/oauth2"
)

const Port = 9011
const ClientID = "client-frontend.localhost"
const ClientSecret = "some-secret"
const Auth2AuthURL = "https://localhost:9000/oauth2/auth"
const Auth2TokenURL = "https://localhost:9000/oauth2/token"
var CallBackURL = fmt.Sprintf("http://%s:%d/login-callback", ClientID, Port)

var Scopes = []string{"openid", "offline"}
var Audience = []string{}
var Prompt = []string{}
var MaxAge = 0

var Ctx = context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}})

func main() {
	r := httprouter.New()
	server := &http.Server{Addr: fmt.Sprintf(":%d", Port), Handler: r}
	r.GET("/consumer/dashboard", handleConsumerDashboardGet)

	r.GET("/login-callback", handleLoginCallback)

	err := server.ListenAndServe()
	panic(err)
}

type State struct {
	RedirectURL string
	Altk string
}

func getAuthURL(state State) (string, error) {
	/*stateRand, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		return "", err
	}*/

	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		return "", err
	}

	conf := getOAuth2Conf()
	stateJson, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	return conf.AuthCodeURL(
		string(stateJson),
		oauth2.SetAuthURLParam("audience", strings.Join(Audience, "+")),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", strings.Join(Prompt, "+")),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(MaxAge)),
	), nil
}

func getOAuth2Conf() oauth2.Config {
	return oauth2.Config{
		ClientID:     ClientID,
		ClientSecret: ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: Auth2TokenURL,
			AuthURL:  Auth2AuthURL,
		},
		RedirectURL: fmt.Sprintf("%s", CallBackURL),
		Scopes:      Scopes,
	}
}

var errorTemplate = template.Must(template.New("").Parse(`<html>
<head></head>
<body>
<h1>Client Frontend Error</h1>
<h2>{{ .Error }}</h2>
</body>
</html>`))

func handleError(w http.ResponseWriter, err error) {
	debug.PrintStack()
	_ = errorTemplate.Execute(w, struct {
		Error string
	}{
		Error: err.Error(),
	})
	return
}
