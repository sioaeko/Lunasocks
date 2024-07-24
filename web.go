package main

import (
    "encoding/json"
    "html/template"
    "net/http"
    "sync"
)

var (
    configMutex sync.RWMutex
)

func StartWebServer(config *Config) error {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        tmpl, err := template.ParseFiles("templates/index.html")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }
        tmpl.Execute(w, nil)
    })

    http.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            configMutex.RLock()
            json.NewEncoder(w).Encode(config)
            configMutex.RUnlock()
        } else if r.Method == "POST" {
            var newConfig Config
            if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
                http.Error(w, err.Error(), http.StatusBadRequest)
                return
            }
            configMutex.Lock()
            *config = newConfig
            configMutex.Unlock()
            w.WriteHeader(http.StatusOK)
        }
    })

    return http.ListenAndServe(":8080", nil)
}
