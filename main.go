package main

import (
    "flag"
    "log"
    "your_project/config"
    "your_project/network"
    "your_project/plugin"
    "your_project/web"
)

func main() {
    // 명령줄 인자 처리
    configFile := flag.String("config", "config.yaml", "Path to configuration file")
    enableTLS := flag.Bool("tls", false, "Enable TLS")
    enableWebAdmin := flag.Bool("web-admin", false, "Enable web admin interface")
    webAdminPort := flag.Int("web-admin-port", 8080, "Web admin interface port")
    flag.Parse()

    // 설정 파일 로드
    cfg, err := config.LoadConfig(*configFile)
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // TLS 설정 적용
    if *enableTLS {
        cfg.UseTLS = true
    }

    // 서버 인스턴스 생성
    server := network.NewServer(cfg)

    // TLS 설정 (설정에서 활성화된 경우)
    if cfg.UseTLS {
        err := server.EnableTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
        if err != nil {
            log.Fatalf("Failed to enable TLS: %v", err)
        }
    }

    // 플러그인 추가
    server.AddPlugin(&plugin.LoggingPlugin{})
    // 추가 플러그인은 여기에 구현

    // 웹 관리 인터페이스 활성화 (명령줄 인자로 지정된 경우)
    if *enableWebAdmin {
        webServer := web.NewWebServer(cfg, server, *webAdminPort)
        go func() {
            if err := webServer.Start(); err != nil {
                log.Fatalf("Web admin interface failed to start: %v", err)
            }
        }()
    }

    // 서버 시작
    if err := server.Start(); err != nil {
        log.Fatalf("Server failed to start: %v", err)
    }
}
