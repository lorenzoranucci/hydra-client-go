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
	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"github.com/ory/x/randx"
	"golang.org/x/oauth2"
)

const Port = 9011
const ClientID = "client-frontend.localhost"
const Auth2AuthURL = "https://www.prontopro.dev/oauth2/auth"
const Auth2TokenURL = "https://www.prontopro.dev/oauth2/token"
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
	Altk *string `json:"Altk,omitempty"`
	ID string
	SocialLoginProvider *string `json:"social_login_provider,omitempty"`
}

var codeVerifiersByState = make(map[string]string)

func getCodeVerifierByState(state State) string {
	s := codeVerifiersByState[state.ID]
	delete(codeVerifiersByState, state.ID)
	return s
}

func getAuthURL(state State) (string, error) {
	stateRand, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		return "", err
	}
	state.ID = string(stateRand)

	nonce, err := randx.RuneSequence(24, randx.AlphaLower)
	if err != nil {
		return "", err
	}

	// initialize the code verifier
	var CodeVerifier, _ = cv.CreateCodeVerifierWithLength(cv.MaxLength)

	// Create code_challenge with S256 method
	codeChallenge := CodeVerifier.CodeChallengeS256()

	conf := getOAuth2Conf()
	stateJson, err := json.Marshal(state)
	if err != nil {
		return "", err
	}

	codeVerifiersByState[state.ID] = string(CodeVerifier.String())
	return conf.AuthCodeURL(
		string(stateJson),
		oauth2.SetAuthURLParam("audience", strings.Join(Audience, "+")),
		oauth2.SetAuthURLParam("nonce", string(nonce)),
		oauth2.SetAuthURLParam("prompt", strings.Join(Prompt, "+")),
		oauth2.SetAuthURLParam("max_age", strconv.Itoa(MaxAge)),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

func getOAuth2Conf() oauth2.Config {
	return oauth2.Config{
		ClientID:     ClientID,
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
