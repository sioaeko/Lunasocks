package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"

	"github.com/sioaeko/Lunasocks/config"
	"github.com/sioaeko/Lunasocks/network"
)

type WebServer struct {
	config *config.Config
	server *network.Server
	port   int
	mu     sync.RWMutex
}

func NewWebServer(cfg *config.Config, server *network.Server, port int) *WebServer {
	return &WebServer{
		config: cfg,
		server: server,
		port:   port,
	}
}

func (ws *WebServer) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", ws.handleIndex)
	mux.HandleFunc("/api/config", ws.handleConfig)
	mux.HandleFunc("/api/server/status", ws.handleServerStatus)

	addr := fmt.Sprintf(":%d", ws.port)
	return http.ListenAndServe(addr, mux)
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func (ws *WebServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		ws.mu.RLock()
		json.NewEncoder(w).Encode(ws.config)
		ws.mu.RUnlock()
	case http.MethodPost:
		var newConfig config.Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		newConfig.Validate()
		ws.mu.Lock()
		*ws.config = newConfig
		ws.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (ws *WebServer) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := struct {
		Running bool   `json:"running"`
		Address string `json:"address"`
	}{
		Running: ws.server.IsRunning(),
		Address: ws.config.ServerAddress,
	}
	json.NewEncoder(w).Encode(status)
}
