package flexbasicauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func newHybridModeHandler(t *testing.T, backend http.Handler) http.Handler {
	t.Helper()

	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Mode = "hybrid"
	cfg.Header = "X-Basic-Auth"
	cfg.CookieName = "flex_basic_auth_session"
	cfg.CookieSecret = "s3cr3t"

	handler, err := New(context.Background(), backend, cfg, "flex-basic-auth-hybrid-test")
	if err != nil {
		t.Fatalf("New() вернул ошибку: %v", err)
	}

	return handler
}

// TestHybridMode_NonBrowserRequiresValidHeader проверяет, что в hybrid mode (в отличие от
// cookie mode) нет bypass по присутствию Authorization: клиент без валидного X-Basic-Auth
// получает 401, даже если несёт какой угодно Authorization.
func TestHybridMode_NonBrowserRequiresValidHeader(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newHybridModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/repo.git/info/refs", nil)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Authorization", "Bearer some-openid-token")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401 без валидного X-Basic-Auth, получен %d", rw.Code)
	}
}

// TestHybridMode_NonBrowserWithValidHeaderPasses проверяет, что валидный configured header
// проходит, а Authorization при этом остаётся нетронутым и доходит до бэкенда.
func TestHybridMode_NonBrowserWithValidHeaderPasses(t *testing.T) {
	var gotAuthorization string

	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotAuthorization = req.Header.Get("Authorization")
		rw.WriteHeader(http.StatusOK)
	})

	handler := newHybridModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/repo.git/info/refs", nil)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Basic-Auth", basicHeader("test", "test"))
	req.Header.Set("Authorization", "Bearer some-openid-token")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("ожидался код 200, получен %d", rw.Code)
	}

	if gotAuthorization != "Bearer some-openid-token" {
		t.Fatalf("Authorization изменён: получено %q", gotAuthorization)
	}
}

// TestHybridMode_BrowserGetsLoginForm проверяет, что браузер (Accept: text/html) без
// валидной куки получает HTML-форму логина, а не 401-challenge от header-mode проверки.
func TestHybridMode_BrowserGetsLoginForm(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newHybridModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/some/protected/page", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}

	if !strings.Contains(rw.Body.String(), `action="/__flexbasicauth/login"`) {
		t.Fatalf("ожидалась HTML-форма логина, body: %s", rw.Body.String())
	}
}

// TestHybridMode_BrowserWithValidCookiePasses проверяет, что валидная сессионная кука
// пропускает браузерный запрос без какого-либо заголовка авторизации.
func TestHybridMode_BrowserWithValidCookiePasses(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newHybridModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
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

func TestNewHybridMode_RequiresCookieNameAndSecret(t *testing.T) {
	cfg := CreateConfig()
	cfg.Users = []string{bcryptUser}
	cfg.Mode = "hybrid"

	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "t"); err == nil {
		t.Fatal("ожидалась ошибка без cookieName/cookieSecret в hybrid mode")
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

func TestSanitizeNext(t *testing.T) {
	tests := map[string]string{
		"":                "/",
		"/foo/bar":        "/foo/bar",
		"//evil.com":      "/",
		"http://evil.com": "/",
		"relative/path":   "/",
	}

	for input, want := range tests {
		if got := sanitizeNext(input); got != want {
			t.Errorf("sanitizeNext(%q) = %q, ожидалось %q", input, got, want)
		}
	}
}

func TestCookieMode_GetWithoutCookieShowsLoginForm(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/some/protected/page", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}

	body := rw.Body.String()
	if !strings.Contains(body, `action="/__flexbasicauth/login"`) {
		t.Fatalf("форма должна постить на loginPath, body: %s", body)
	}

	if !strings.Contains(body, `value="/some/protected/page"`) {
		t.Fatalf("next должен указывать на исходный URL, body: %s", body)
	}
}

func TestCookieMode_LoginSuccessSetsCookieAndRedirects(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	form := url.Values{"username": {"test"}, "password": {"test"}, "next": {"/some/protected/page"}}
	req := httptest.NewRequest(http.MethodPost, "/__flexbasicauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusFound {
		t.Fatalf("ожидался код 302, получен %d", rw.Code)
	}

	if loc := rw.Header().Get("Location"); loc != "/some/protected/page" {
		t.Fatalf("Location = %q, ожидалось %q", loc, "/some/protected/page")
	}

	cookies := rw.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "flex_basic_auth_session" {
		t.Fatalf("ожидалась кука flex_basic_auth_session, получено %v", cookies)
	}

	if !cookies[0].HttpOnly || !cookies[0].Secure {
		t.Fatal("кука должна быть HttpOnly и Secure")
	}

	username, ok := verifySession(cookies[0].Value, "s3cr3t")
	if !ok || username != "test" {
		t.Fatalf("кука должна быть валидна для test, получено username=%q ok=%v", username, ok)
	}
}

func TestCookieMode_LoginSuccessSanitizesOpenRedirect(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	form := url.Values{"username": {"test"}, "password": {"test"}, "next": {"//evil.com"}}
	req := httptest.NewRequest(http.MethodPost, "/__flexbasicauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if loc := rw.Header().Get("Location"); loc != "/" {
		t.Fatalf("Location = %q, ожидалось %q (open redirect не должен проходить)", loc, "/")
	}
}

func TestCookieMode_LoginWrongPassword(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	form := url.Values{"username": {"test"}, "password": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/__flexbasicauth/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}

	if len(rw.Result().Cookies()) != 0 {
		t.Fatal("при неверном пароле кука не должна выставляться")
	}

	if !strings.Contains(rw.Body.String(), "Invalid username or password") {
		t.Fatal("ожидалось сообщение об ошибке в форме")
	}
}

// TestCookieMode_NonBrowserGetsWWWAuthenticate — регрессия на кейс "git push ломается":
// клиенты без Accept: text/html (git/curl/API) должны получать обычный 401 +
// WWW-Authenticate: Basic, а не HTML-форму, иначе они не поймут, что нужно повторить
// запрос с Authorization (который дальше ушёл бы напрямую в бэкенд по bypass-правилу).
func TestCookieMode_NonBrowserGetsWWWAuthenticate(t *testing.T) {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})

	handler := newCookieModeHandler(t, backend)

	req := httptest.NewRequest(http.MethodGet, "/absolem/repo.git/info/refs", nil)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("User-Agent", "git/2.50.1")
	rw := httptest.NewRecorder()

	handler.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался код 401, получен %d", rw.Code)
	}

	if got := rw.Header().Get("WWW-Authenticate"); got != `Basic realm="traefik"` {
		t.Fatalf("WWW-Authenticate = %q, ожидалось Basic-challenge", got)
	}

	if strings.Contains(rw.Body.String(), "<form") {
		t.Fatal("нечто-браузерному клиенту не должна отдаваться HTML-форма логина")
	}
}
