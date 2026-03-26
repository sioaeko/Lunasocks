package main

import (
	"flag"
	"log"

	"github.com/sioaeko/Lunasocks/config"
	"github.com/sioaeko/Lunasocks/logging"
	"github.com/sioaeko/Lunasocks/network"
	"github.com/sioaeko/Lunasocks/plugin"
	"github.com/sioaeko/Lunasocks/web"
)

func main() {
	configFile := flag.String("config", "config.yaml", "Path to configuration file")
	enableTLS := flag.Bool("tls", false, "Enable TLS")
	enableWebAdmin := flag.Bool("web-admin", false, "Enable web admin interface")
	webAdminPort := flag.Int("web-admin-port", 8080, "Web admin interface port")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, error)")
	flag.Parse()

	logging.SetLogLevel(*logLevel)

	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *enableTLS {
		cfg.UseTLS = true
	}

	server := network.NewServer(cfg)

	if cfg.UseTLS {
		if err := server.EnableTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			log.Fatalf("Failed to enable TLS: %v", err)
		}
	}

	server.AddPlugin(&plugin.LoggingPlugin{})

	if *enableWebAdmin {
		webServer := web.NewWebServer(cfg, server, *webAdminPort)
		go func() {
			log.Printf("Web admin interface starting on :%d", *webAdminPort)
			if err := webServer.Start(); err != nil {
				log.Fatalf("Web admin interface failed: %v", err)
			}
		}()
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
