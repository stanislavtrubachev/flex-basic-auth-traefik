// Локальный сервер для ручной проверки middleware без подъёма Traefik.
package main

import (
	"context"
	"log"
	"net/http"

	flexbasicauth "github.com/stanislavtrubachev/flex-basic-auth-traefik"
)

func main() {
	backend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)

		for name, values := range req.Header {
			for _, v := range values {
				_, _ = rw.Write([]byte(name + ": " + v + "\n"))
			}
		}
	})

	cfg := flexbasicauth.CreateConfig()
	cfg.Header = "X-Basic-Auth"
	cfg.RemoveHeader = true
	cfg.HeaderField = "X-Authenticated-User"
	cfg.Users = []string{
		"test:$2y$05$M8UUkM3YUg2Is4G9Im5R8eYBJM6I5efzIIJ0mkfUsaAU8Cyo5/7LG", // test:test (bcrypt)
		"aprtest:$apr1$saltsalt$NBMPZFGR7yazCdGvlWJji1",                    // aprtest:test (apr1)
		"shatest:{SHA}qUqP5cyxm6YcTAhz05Hph5gvu9M=",                        // shatest:test (SHA1)
	}

	handler, err := flexbasicauth.New(context.Background(), backend, cfg, "flex-basic-auth-dev")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("listening on :8080, header =", cfg.Header)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
