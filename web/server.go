package web

import (
    "encoding/json"
    "fmt"
    "html/template"
    "net/http"
    "your_project/config"
    "your_project/network"
)

type WebServer struct {
    config *config.Config
    server *network.Server
    port   int
}

func NewWebServer(cfg *config.Config, server *network.Server, port int) *WebServer {
    return &WebServer{
        config: cfg,
        server: server,
        port:   port,
    }
}

func (ws *WebServer) Start() error {
    http.HandleFunc("/", ws.handleIndex)
    http.HandleFunc("/api/config", ws.handleConfig)
    http.HandleFunc("/api/server/status", ws.handleServerStatus)

    return http.ListenAndServe(fmt.Sprintf(":%d", ws.port), nil)
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
    tmpl, err := template.ParseFiles("templates/index.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    tmpl.Execute(w, nil)
}

func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        json.NewEncoder(w).Encode(ws.config)
    } else if r.Method == "POST" {
        var newConfig config.Config
        if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        *ws.config = newConfig
        w.WriteHeader(http.StatusOK)
    }
}

func (ws *WebServer) handleServerStatus(w http.ResponseWriter, r *http.Request) {
    status := struct {
        Running bool `json:"running"`
    }{
        Running: ws.server.IsRunning(),
    }
    json.NewEncoder(w).Encode(status)
}
