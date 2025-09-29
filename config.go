package main

import (
	"log"
	"os"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type Config struct {
	OAuthID       string `conf:"OAUTH_ID"`
	OAuthSecret   string `conf:"OAUTH_SECRET"`
	OAuthScopes   string `conf:"OAUTH_SCOPES,email;openid;profile;offline_access"`
	OAuthAuthURL  string `conf:"OAUTH_AUTH_URL"`
	OAuthTokenURL string `conf:"OAUTH_TOKEN_URL"`

	DatabaseUrl string `conf:"DATABASE_URL,file:data.db"`

	WebPort string `conf:"WEB_PORT,8080"`
	SshPort string `conf:"SSH_PORT,2222"`
}

func (c *Config) OAuthConfig(ctx *gin.Context) oauth2.Config {
	conf := oauth2.Config{
		ClientID:     c.OAuthID,
		ClientSecret: c.OAuthSecret,
		Scopes:       strings.Split(c.OAuthScopes, ","),
		Endpoint: oauth2.Endpoint{
			AuthURL:  c.OAuthAuthURL,
			TokenURL: c.OAuthTokenURL,
		},
	}

	// if ctx is given, set redirect URL based on request
	if ctx != nil {
		var scheme string
		if ctx.Request.Header.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		} else {
			scheme = "http"
		}
		conf.RedirectURL = scheme + "://" + ctx.Request.Host + "/auth/callback"
	}

	return conf
}

var config Config

func init() {
	// load config from env
	st := reflect.ValueOf(&config).Elem()

	missingConfig := false
	for i := 0; i < st.NumField(); i++ {
		field := st.Field(i)
		fieldType := st.Type().Field(i)

		// get conf tag and skip this field if tag does not exist
		tag, ok := fieldType.Tag.Lookup("conf")
		if !ok {
			continue
		}
		splitTag := strings.Split(tag, ",")

		// check if default value exists
		var defaultValue string
		if len(splitTag) > 1 {
			defaultValue = strings.ReplaceAll(splitTag[1], ";", ",")
		}

		// get value from env
		value, valueGiven := os.LookupEnv(splitTag[0])

		// use default value if no value given
		if !valueGiven {
			value = defaultValue
		}

		// check if value is empty
		if value == "" {
			missingConfig = true
			log.Printf("Missing config for %s", splitTag[0])
		}

		// set value in struct
		switch fieldType.Type.Kind() {
		case reflect.String:
			field.SetString(value)

		default:
			panic("unsupported struct field type")
		}
	}

	// check required fields
	if missingConfig {
		log.Fatal("Missing required config")
	}
}
