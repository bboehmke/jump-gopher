package main

import (
	"log/slog"
	"os"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// Config holds all configuration values for the application, loaded from environment variables.
type Config struct {
	OAuthID       string `conf:"OAUTH_ID"`
	OAuthSecret   string `conf:"OAUTH_SECRET"`
	OAuthScopes   string `conf:"OAUTH_SCOPES,email;openid;profile;offline_access"`
	OAuthAuthURL  string `conf:"OAUTH_AUTH_URL"`
	OAuthTokenURL string `conf:"OAUTH_TOKEN_URL"`

	DatabaseUrl string `conf:"DATABASE_URL,file:data/data.db"`

	WebPort        string `conf:"WEB_PORT,8080"`
	WebEnableProxy string `conf:"WEB_ENABLE_PROXY,false"`
	WebDebug       string `conf:"WEB_DEBUG,false"`

	SshPort        string `conf:"SSH_PORT,2222"`
	SshHostKeyPath string `conf:"SSH_HOST_KEY_PATH,data/"`

	PermissionsConfig string `conf:"PERMISSIONS_CONFIG,data/permissions.yml"`
}

// OAuthConfig returns an oauth2.Config for the current configuration and request context.
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

		// ignore oauth config in check mode
		if *checkConfig && strings.HasPrefix(strings.ToLower(tag), "oauth_") {
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
			slog.Error("Missing config for " + splitTag[0])
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
		slog.Error("Missing required config")
	}
}
