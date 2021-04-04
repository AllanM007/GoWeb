package basic-middleware

import (
    "fmt"
    "log"
    "net/http"
)

func Logging(f http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        log.Println(r.URL.Path)
        f(w, r)
    }
}