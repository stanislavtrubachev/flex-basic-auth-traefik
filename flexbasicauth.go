// Package flexbasicauth реализует Traefik middleware-плагин, аналогичный
// встроенному BasicAuth, но читающий учётные данные из настраиваемого
// заголовка запроса, а не только из Authorization.
package flexbasicauth

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Config — конфигурация плагина.
type Config struct {
	Users        []string `json:"users,omitempty" yaml:"users,omitempty" toml:"users,omitempty"`
	Header       string   `json:"header,omitempty" yaml:"header,omitempty" toml:"header,omitempty"`
	Realm        string   `json:"realm,omitempty" yaml:"realm,omitempty" toml:"realm,omitempty"`
	RemoveHeader bool     `json:"removeHeader,omitempty" yaml:"removeHeader,omitempty" toml:"removeHeader,omitempty"`
	HeaderField  string   `json:"headerField,omitempty" yaml:"headerField,omitempty" toml:"headerField,omitempty"`

	// Mode выбирает режим работы: "header" (по умолчанию, чтение Basic-креденшлов
	// из заголовка) или "cookie" (форма логина + подписанная сессионная кука).
	Mode         string `json:"mode,omitempty" yaml:"mode,omitempty" toml:"mode,omitempty"`
	CookieName   string `json:"cookieName,omitempty" yaml:"cookieName,omitempty" toml:"cookieName,omitempty"`
	CookieSecret string `json:"cookieSecret,omitempty" yaml:"cookieSecret,omitempty" toml:"cookieSecret,omitempty"`
	CookieTTL    string `json:"cookieTTL,omitempty" yaml:"cookieTTL,omitempty" toml:"cookieTTL,omitempty"`
	LoginPath    string `json:"loginPath,omitempty" yaml:"loginPath,omitempty" toml:"loginPath,omitempty"`
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
	users        map[string]string

	mode         string
	cookieName   string
	cookieSecret string
	cookieTTL    time.Duration
	loginPath    string
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

	users, err := parseUsers(config.Users)
	if err != nil {
		return nil, err
	}

	if len(users) == 0 {
		return nil, fmt.Errorf("users list cannot be empty")
	}

	mode := config.Mode
	if mode == "" {
		mode = "header"
	}

	if mode != "header" && mode != "cookie" {
		return nil, fmt.Errorf("invalid mode %q: must be \"header\" or \"cookie\"", mode)
	}

	var cookieName, cookieSecret, loginPath string

	var cookieTTL time.Duration

	if mode == "cookie" {
		cookieName = config.CookieName
		if cookieName == "" {
			return nil, fmt.Errorf("cookieName is required in cookie mode")
		}

		cookieSecret = config.CookieSecret
		if cookieSecret == "" {
			return nil, fmt.Errorf("cookieSecret is required in cookie mode")
		}

		loginPath = config.LoginPath
		if loginPath == "" {
			loginPath = "/__flexbasicauth/login"
		}

		ttlStr := config.CookieTTL
		if ttlStr == "" {
			ttlStr = "24h"
		}

		cookieTTL, err = time.ParseDuration(ttlStr)
		if err != nil {
			return nil, fmt.Errorf("invalid cookieTTL %q: %w", ttlStr, err)
		}
	}

	return &FlexBasicAuth{
		next:         next,
		name:         name,
		header:       header,
		realm:        realm,
		removeHeader: config.RemoveHeader,
		headerField:  config.HeaderField,
		users:        users,
		mode:         mode,
		cookieName:   cookieName,
		cookieSecret: cookieSecret,
		cookieTTL:    cookieTTL,
		loginPath:    loginPath,
	}, nil
}

func (f *FlexBasicAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if f.mode == "cookie" {
		f.serveCookieMode(rw, req)
		return
	}

	f.serveHeaderMode(rw, req)
}

func (f *FlexBasicAuth) serveHeaderMode(rw http.ResponseWriter, req *http.Request) {
	headerValue := req.Header.Get(f.header)

	username, password, ok := parseBasicAuth(headerValue)
	if !ok || !f.validate(username, password) {
		f.unauthorized(rw)
		return
	}

	if f.removeHeader {
		req.Header.Del(f.header)
	}

	if f.headerField != "" {
		req.Header.Set(f.headerField, username)
	}

	f.next.ServeHTTP(rw, req)
}

// serveCookieMode: если в запросе уже есть Authorization — не вмешиваемся (git/API/OIDC
// проходят как есть). Иначе ищем валидную сессионную куку. Форма логина появится на
// следующем этапе — пока при её отсутствии просто отказ.
func (f *FlexBasicAuth) serveCookieMode(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != "" {
		f.next.ServeHTTP(rw, req)
		return
	}

	cookie, err := req.Cookie(f.cookieName)
	if err == nil {
		if _, ok := verifySession(cookie.Value, f.cookieSecret); ok {
			f.next.ServeHTTP(rw, req)
			return
		}
	}

	rw.WriteHeader(http.StatusUnauthorized)
}

// signSession подписывает "<username>.<unix-время истечения>" через HMAC-SHA256.
func signSession(username string, expiry time.Time, secret string) string {
	payload := username + "." + strconv.FormatInt(expiry.Unix(), 10)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))

	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

// verifySession проверяет подпись и срок действия куки, выставленной signSession.
func verifySession(value, secret string) (username string, ok bool) {
	parts := strings.SplitN(value, ".", 3)
	if len(parts) != 3 {
		return "", false
	}

	username, expiryStr, sig := parts[0], parts[1], parts[2]

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(username + "." + expiryStr))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}

	expiryUnix, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return "", false
	}

	if time.Now().Unix() > expiryUnix {
		return "", false
	}

	return username, true
}

func (f *FlexBasicAuth) validate(username, password string) bool {
	hash, ok := f.users[username]
	if !ok {
		return false
	}

	ok, err := verifyPassword(password, hash)
	if err != nil {
		return false
	}

	return ok
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

// parseUsers разбирает список users в формате "login:htpasswd-хэш".
func parseUsers(list []string) (map[string]string, error) {
	users := make(map[string]string, len(list))

	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" || strings.HasPrefix(entry, "#") {
			continue
		}

		idx := strings.IndexByte(entry, ':')
		if idx <= 0 || idx == len(entry)-1 {
			return nil, fmt.Errorf("invalid user entry %q: expected format \"login:hash\"", entry)
		}

		users[entry[:idx]] = entry[idx+1:]
	}

	return users, nil
}

// verifyPassword сравнивает пароль с htpasswd-хэшем. Поддерживаются форматы
// bcrypt ($2a$/$2b$/$2y$), MD5-crypt ($apr1$/$1$) и SHA1 ({SHA})
// как и во встроенном BasicAuth Traefik.
func verifyPassword(password, hash string) (bool, error) {
	switch {
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return err == nil, nil

	case strings.HasPrefix(hash, "$apr1$"), strings.HasPrefix(hash, "$1$"):
		computed, err := md5Crypt(password, hash)
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1, nil

	case strings.HasPrefix(hash, "{SHA}"):
		sum := sha1.Sum([]byte(password))
		computed := "{SHA}" + base64.StdEncoding.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1, nil

	default:
		return false, fmt.Errorf("unsupported password hash format")
	}
}

// md5Crypt вычисляет MD5-crypt хэш (алгоритм FreeBSD/Apache apr1) для пароля,
// используя соль и magic-строку ("1" или "apr1"), извлечённые из образца хэша.
func md5Crypt(password, sample string) (string, error) {
	parts := strings.Split(sample, "$")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid md5-crypt hash format")
	}

	magic := parts[1]
	if magic != "1" && magic != "apr1" {
		return "", fmt.Errorf("unsupported md5-crypt magic %q", magic)
	}

	salt := parts[2]
	if len(salt) > 8 {
		salt = salt[:8]
	}

	return md5CryptCompute(password, salt, magic), nil
}

const md5CryptAlphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func md5CryptCompute(password, salt, magic string) string {
	pwd := []byte(password)

	ctx1 := md5.New()
	ctx1.Write(pwd)
	ctx1.Write([]byte("$"))
	ctx1.Write([]byte(magic))
	ctx1.Write([]byte("$"))
	ctx1.Write([]byte(salt))

	ctx2 := md5.New()
	ctx2.Write(pwd)
	ctx2.Write([]byte(salt))
	ctx2.Write(pwd)
	final := ctx2.Sum(nil)

	for pl := len(pwd); pl > 0; pl -= 16 {
		n := pl
		if n > 16 {
			n = 16
		}
		ctx1.Write(final[:n])
	}

	for i := len(pwd); i != 0; i >>= 1 {
		if i&1 != 0 {
			ctx1.Write([]byte{0})
		} else {
			ctx1.Write(pwd[:1])
		}
	}

	result := ctx1.Sum(nil)

	for i := 0; i < 1000; i++ {
		ctx3 := md5.New()

		if i&1 != 0 {
			ctx3.Write(pwd)
		} else {
			ctx3.Write(result)
		}

		if i%3 != 0 {
			ctx3.Write([]byte(salt))
		}

		if i%7 != 0 {
			ctx3.Write(pwd)
		}

		if i&1 != 0 {
			ctx3.Write(result)
		} else {
			ctx3.Write(pwd)
		}

		result = ctx3.Sum(nil)
	}

	var sb strings.Builder
	sb.WriteByte('$')
	sb.WriteString(magic)
	sb.WriteByte('$')
	sb.WriteString(salt)
	sb.WriteByte('$')

	triplets := [5][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}}
	for _, t := range triplets {
		v := uint32(result[t[0]])<<16 | uint32(result[t[1]])<<8 | uint32(result[t[2]])
		sb.WriteString(to64(v, 4))
	}
	sb.WriteString(to64(uint32(result[11]), 2))

	return sb.String()
}

func to64(value uint32, size int) string {
	buf := make([]byte, size)
	for i := 0; i < size; i++ {
		buf[i] = md5CryptAlphabet[value&0x3f]
		value >>= 6
	}
	return string(buf)
}
