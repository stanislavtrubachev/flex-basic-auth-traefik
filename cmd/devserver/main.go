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

	handler, err := flexbasicauth.New(context.Background(), backend, cfg, "flex-basic-auth-dev")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("listening on :8080, header =", cfg.Header)
	log.Fatal(http.ListenAndServe(":8080", handler))
}
