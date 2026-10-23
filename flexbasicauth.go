// Package flexbasicauth реализует Traefik middleware-плагин, аналогичный
// встроенному BasicAuth, но читающий учётные данные из настраиваемого
// заголовка запроса, а не только из Authorization.
package flexbasicauth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// Config — конфигурация плагина.
type Config struct {
	Users        []string `json:"users,omitempty" yaml:"users,omitempty" toml:"users,omitempty"`
	Header       string   `json:"header,omitempty" yaml:"header,omitempty" toml:"header,omitempty"`
	Realm        string   `json:"realm,omitempty" yaml:"realm,omitempty" toml:"realm,omitempty"`
	RemoveHeader bool     `json:"removeHeader,omitempty" yaml:"removeHeader,omitempty" toml:"removeHeader,omitempty"`
	HeaderField  string   `json:"headerField,omitempty" yaml:"headerField,omitempty" toml:"headerField,omitempty"`
}

// CreateConfig создаёт конфигурацию плагина со значениями по умолчанию.
func CreateConfig() *Config {
	return &Config{
		Header: "Authorization",
		Realm:  "traefik",
	}
}

// FlexBasicAuth — middleware-обработчик.
type FlexBasicAuth struct {
	next         http.Handler
	name         string
	header       string
	realm        string
	removeHeader bool
	headerField  string
}

// New создаёт экземпляр middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	header := config.Header
	if header == "" {
		header = "Authorization"
	}

	realm := config.Realm
	if realm == "" {
		realm = "traefik"
	}

	return &FlexBasicAuth{
		next:         next,
		name:         name,
		header:       header,
		realm:        realm,
		removeHeader: config.RemoveHeader,
		headerField:  config.HeaderField,
	}, nil
}

func (f *FlexBasicAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	headerValue := req.Header.Get(f.header)

	_, _, ok := parseBasicAuth(headerValue)
	if !ok {
		f.unauthorized(rw)
		return
	}

	// Проверка пароля по списку users появится на следующем этапе.
	f.next.ServeHTTP(rw, req)
}

func (f *FlexBasicAuth) unauthorized(rw http.ResponseWriter) {
	rw.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, f.realm))
	rw.WriteHeader(http.StatusUnauthorized)
}

// parseBasicAuth разбирает значение заголовка вида "Basic <base64(login:password)>".
func parseBasicAuth(headerValue string) (username, password string, ok bool) {
	const prefix = "Basic "

	if len(headerValue) <= len(prefix) || !strings.EqualFold(headerValue[:len(prefix)], prefix) {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(headerValue[len(prefix):])
	if err != nil {
		return "", "", false
	}

	pair := string(decoded)

	idx := strings.IndexByte(pair, ':')
	if idx < 0 {
		return "", "", false
	}

	return pair[:idx], pair[idx+1:], true
}
