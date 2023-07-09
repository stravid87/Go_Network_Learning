package main

import (
    "log"
    "net/http"
)

func main() {
    fs := http.FileServer(http.Dir("../../frontend"))
    http.Handle("/", corsMiddleware(fs))

    log.Println("Listening on http://localhost:8080/index.html")
    err := http.ListenAndServe(":8080", nil)
    if err != nil {
        log.Fatal(err)
    }
}

// First server is running on :9090
// Second server is running on :9091
// Front sever is running on :8080

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*") 
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
        next.ServeHTTP(w, r)
    })
}