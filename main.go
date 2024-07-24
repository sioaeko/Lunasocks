package main

import (
    "log"
    "your_project/config"
    "your_project/network"
)

func main() {
    // 설정 파일 로드
    cfg, err := config.LoadConfig("config.yaml")
    if err != nil {
        log.Fatalf("Failed to load config: %v", err)
    }

    // 서버 인스턴스 생성
    server := network.NewServer(cfg)

    // 서버 시작
    if err := server.Start(); err != nil {
        log.Fatalf("Server failed to start: %v", err)
    }
}
