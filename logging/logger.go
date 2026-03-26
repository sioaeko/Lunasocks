package logging

import (
	"fmt"
	"log"
	"os"
	"sync"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
	debugLogger *log.Logger
	logLevel    = LevelInfo
	mu          sync.RWMutex
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelError
)

func init() {
	infoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	debugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func SetLogLevel(level string) {
	mu.Lock()
	defer mu.Unlock()
	switch level {
	case "debug":
		logLevel = LevelDebug
	case "info":
		logLevel = LevelInfo
	case "error":
		logLevel = LevelError
	default:
		logLevel = LevelInfo
	}
}

func GetLogLevel() Level {
	mu.RLock()
	defer mu.RUnlock()
	return logLevel
}

func Debug(format string, v ...any) {
	if GetLogLevel() <= LevelDebug {
		debugLogger.Output(2, fmt.Sprintf(format, v...))
	}
}

func Info(format string, v ...any) {
	if GetLogLevel() <= LevelInfo {
		infoLogger.Output(2, fmt.Sprintf(format, v...))
	}
}

func Error(format string, v ...any) {
	if GetLogLevel() <= LevelError {
		errorLogger.Output(2, fmt.Sprintf(format, v...))
	}
}
