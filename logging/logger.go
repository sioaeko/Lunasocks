package logging

import (
    "log"
    "os"
    "sync"
)

var (
    infoLogger  *log.Logger
    errorLogger *log.Logger
    debugLogger *log.Logger
    logLevel    = "info"
    mu          sync.Mutex
)

func init() {
    infoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
    errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
    debugLogger = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func SetLogLevel(level string
