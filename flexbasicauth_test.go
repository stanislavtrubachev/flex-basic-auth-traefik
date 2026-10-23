package flexbasicauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	bcryptUser = "test:$2y$05$M8UUkM3YUg2Is4G9Im5R8eYBJM6I5efzIIJ0mkfUsaAU8Cyo5/7LG" // test:test
	apr1User   = "aprtest:$apr1$saltsalt$NBMPZFGR7yazCdGvlWJji1"                     // aprtest:test
	sha1User   = "shatest:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M="                         // shatest:test
)

func basicHeader(login, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(login+":"+password))
}

func newTestHandler(t *testing.T, cfg *Config) http.Handler {
	t.Helper()

	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), backend, cfg, "flex-basic-auth-test")
	if err != nil {
		t.Fatalf("New() вернул ошибку: %v", err)
	}

	return handler
}

func TestNewRejectsEmptyUsers(t *testing.T) {
	cfg := CreateConfig()

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("ожидалась ошибка при пустом списке users")
	}
}

func TestNewRejectsInvalidUserEntry(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{"malformed-entry-without-colon"}

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("ожидалась ошибка при некорректной записи users")
	}
}

func TestServeHTTP_SuccessfulAuth(t *testing.T) {
	tests := []struct {
		name     string
		userLine string
		login    string
		password string
	}{
		{"bcrypt", bcryptUser, "test", "test"},
		{"apr1", apr1User, "aprtest", "test"},
		{"sha1", sha1User, "shatest", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := CreateConfig()
			cfg.Users = []string{tt.userLine}

			handler := newTestHandler(t, cfg)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", basicHeader(tt.login, tt.password))
			rw := httptest.NewRecorder()

			handler.ServeHTTP(rw, req)

			if rw.Code != http.StatusOK {
				t.Fatalf("ожидался код 200, получен %d", rw.Code)
			}
		})
	}
}

func TestServeHTTP_WrongPassword(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}

	handler := newTestHandler(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicHeader("test", "wrong-password"))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}
}

func TestServeHTTP_UnknownUser(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}

	handler := newTestHandler(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicHeader("nouser", "test"))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}
}

func TestServeHTTP_MissingHeader(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}

	handler := newTestHandler(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}

	want := `Basic realm="traefik"`
	if got := rw.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate = %q, ожидалось %q", got, want)
	}
}

func TestServeHTTP_MalformedHeader(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}

	handler := newTestHandler(t, cfg)

	tests := []string{
		"Bearer sometoken",
		"Basic not-valid-base64!!!",
		"Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")),
	}

	for _, headerValue := range tests {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", headerValue)
		rw := httptest.NewRecorder()

		handler.ServeHTTP(rw, req)

		if rw.Code != http.StatusUnauthorized {
			t.Fatalf("для %q ожидался код 401, получен %d", headerValue, rw.Code)
		}
	}
}

func TestServeHTTP_CustomRealm(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Realm = "my-realm"

	handler := newTestHandler(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	want := `Basic realm="my-realm"`
	if got := rw.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate = %q, ожидалось %q", got, want)
	}
}

func TestServeHTTP_CustomHeader(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Header = "X-Basic-Auth"

	handler := newTestHandler(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Basic-Auth", basicHeader("test", "test"))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200, получен %d", rw.Code)
	}
}

// TestServeHTTP_CoexistsWithBearerAuthorization проверяет ключевое требование:
// при кастомном header заголовок Authorization не читается и не изменяется,
// поэтому "Authorization: Bearer ..." доходит до бэкенда нетронутым.
func TestServeHTTP_CoexistsWithBearerAuthorization(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Header = "X-Basic-Auth"

	var gotAuthorization string
	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotAuthorization = req.Header.Get("Authorization")
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), backend, cfg, "flex-basic-auth-test")
	if err != nil {
		t.Fatalf("New() вернул ошибку: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Basic-Auth", basicHeader("test", "test"))
	req.Header.Set("Authorization", "Bearer some-openid-token")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200, получен %d", rw.Code)
	}

	if gotAuthorization != "Bearer some-openid-token" {
		t.Fatalf("Authorization изменён: получено %q, ожидалось %q", gotAuthorization, "Bearer some-openid-token")
	}
}

func TestServeHTTP_RemoveHeader(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Header = "X-Basic-Auth"
	cfg.RemoveHeader = true

	var gotHeader string
	headerPresent := true
	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotHeader = req.Header.Get("X-Basic-Auth")
		_, headerPresent = req.Header["X-Basic-Auth"]
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), backend, cfg, "flex-basic-auth-test")
	if err != nil {
		t.Fatalf("New() вернул ошибку: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Basic-Auth", basicHeader("test", "test"))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200, получен %d", rw.Code)
	}

	if headerPresent || gotHeader != "" {
		t.Fatalf("заголовок X-Basic-Auth должен быть удалён, получено %q", gotHeader)
	}
}

func TestServeHTTP_HeaderField(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.HeaderField = "X-Authenticated-User"

	var gotUser string
	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotUser = req.Header.Get("X-Authenticated-User")
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), backend, cfg, "flex-basic-auth-test")
	if err != nil {
		t.Fatalf("New() вернул ошибку: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicHeader("test", "test"))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200, получен %d", rw.Code)
	}

	if gotUser != "test" {
		t.Fatalf("X-Authenticated-User = %q, ожидалось %q", gotUser, "test")
	}
}

func TestServeHTTP_HeaderFieldEmptyMeansNotSet(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}

	var headerPresent bool
	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, headerPresent = req.Header["X-Authenticated-User"]
		rw.WriteHeader(http.StatusOK)
	})

	handler, err := New(context.Background(), backend, cfg, "flex-basic-auth-test")
	if err != nil {
		t.Fatalf("New() вернул ошибку: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicHeader("test", "test"))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if headerPresent {
		t.Fatal("заголовок X-Authenticated-User не должен выставляться при пустом headerField")
	}
}

// TestTraefikManifestTestData проверяет, что testData из .traefik.yml
// действительно принимает пароль "test" для пользователя "test".
func TestTraefikManifestTestData(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{"test:$apr1$H6uskkkW$IgXLP6ewTrSuBkTrqE8wj/"}

	handler := newTestHandler(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", basicHeader("test", "test"))
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("testData из .traefik.yml не проходит проверку: код %d", rw.Code)
	}
}

func TestSignVerifySessionRoundTrip(t *testing.T) {
	value := signSession("alice", time.Now().Add(time.Hour), "s3cr3t")

	username, ok := verifySession(value, "s3cr3t")
	if !ok {
		t.Fatal("ожидалась валидная кука")
	}

	if username != "alice" {
		t.Fatalf("username = %q, ожидалось %q", username, "alice")
	}
}

func TestVerifySessionExpired(t *testing.T) {
	value := signSession("alice", time.Now().Add(-time.Hour), "s3cr3t")

	if _, ok := verifySession(value, "s3cr3t"); ok {
		t.Fatal("просроченная кука не должна проходить проверку")
	}
}

func TestVerifySessionWrongSecret(t *testing.T) {
	value := signSession("alice", time.Now().Add(time.Hour), "s3cr3t")

	if _, ok := verifySession(value, "wrong-secret"); ok {
		t.Fatal("кука с неверным секретом не должна проходить проверку")
	}
}

func TestVerifySessionTampered(t *testing.T) {
	value := signSession("alice", time.Now().Add(time.Hour), "s3cr3t")
	tampered := "bob" + value[len("alice"):]

	if _, ok := verifySession(tampered, "s3cr3t"); ok {
		t.Fatal("подделанная кука (другой username) не должна проходить проверку")
	}
}

func TestVerifySessionMalformed(t *testing.T) {
	for _, v := range []string{"", "no-dots-at-all", "a.b", "a.b.c.d"} {
		if _, ok := verifySession(v, "s3cr3t"); ok {
			t.Fatalf("malformed-значение %q не должно проходить проверку", v)
		}
	}
}

func TestNewCookieMode_RequiresCookieNameAndSecret(t *testing.T) {
	base := func() *Config {
		cfg := CreateConfig()
		cfg.Users = []string{bcryptUser}
		cfg.Mode = "cookie"
		return cfg
	}

	if _, err := New(context.Background(), http.NotFoundHandler(), base(), "t"); err == nil {
		t.Fatal("ожидалась ошибка без cookieName/cookieSecret")
	}

	cfg := base()
	cfg.CookieName = "flex_basic_auth_session"

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "t"); err == nil {
		t.Fatal("ожидалась ошибка без cookieSecret")
	}
}

func TestNewCookieMode_InvalidTTL(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Mode = "cookie"
	cfg.CookieName = "flex_basic_auth_session"
	cfg.CookieSecret = "s3cr3t"
	cfg.CookieTTL = "not-a-duration"

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "t"); err == nil {
		t.Fatal("ожидалась ошибка на невалидный cookieTTL")
	}
}

func TestNewInvalidMode(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Mode = "something-else"

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "t"); err == nil {
		t.Fatal("ожидалась ошибка на неизвестный mode")
	}
}

func newCookieModeHandler(t *testing.T, backend http.Handler) http.Handler {
	t.Helper()

	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Mode = "cookie"
	cfg.CookieName = "flex_basic_auth_session"
	cfg.CookieSecret = "s3cr3t"

	handler, err := New(context.Background(), backend, cfg, "flex-basic-auth-cookie-test")
	if err != nil {
		t.Fatalf("New() вернул ошибку: %v", err)
	}

	return handler
}

func TestCookieMode_BypassOnAuthorization(t *testing.T) {
	var gotAuthorization string

	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotAuthorization = req.Header.Get("Authorization")
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-openid-token")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200 (bypass), получен %d", rw.Code)
	}

	if gotAuthorization != "Bearer some-openid-token" {
		t.Fatalf("Authorization изменён: получено %q", gotAuthorization)
	}
}

func TestCookieMode_ValidCookiePassesThrough(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "flex_basic_auth_session",
		Value: signSession("test", time.Now().Add(time.Hour), "s3cr3t"),
	})
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200, получен %d", rw.Code)
	}
}

func TestCookieMode_MissingCookieUnauthorized(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}
}

func TestCookieMode_OtherCookiesUntouched(t *testing.T) {
	var gotCookieHeader string

	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotCookieHeader = req.Header.Get("Cookie")
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "i_like_gitea", Value: "some-gitea-session"})
	req.AddCookie(&http.Cookie{
		Name:  "flex_basic_auth_session",
		Value: signSession("test", time.Now().Add(time.Hour), "s3cr3t"),
	})
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200, получен %d", rw.Code)
	}

	if !strings.Contains(gotCookieHeader, "i_like_gitea=some-gitea-session") {
		t.Fatalf("чужая кука потерялась при проксировании: Cookie=%q", gotCookieHeader)
	}
}
