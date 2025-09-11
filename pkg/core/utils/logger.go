package utils

import (
	"fmt"
	"time"

	"github.com/StreamDeploy/streamdeploy-agent/pkg/core/types"
)

type SimpleLogger struct {
	prefix string
}

// NewLogger creates a new simple logger
func NewLogger(prefix string) types.Logger {
	return &SimpleLogger{
		prefix: prefix,
	}
}

// Info logs an info message
func (l *SimpleLogger) Info(msg string) {
	l.log("INFO", msg)
}

// Error logs an error message
func (l *SimpleLogger) Error(msg string) {
	l.log("ERROR", msg)
}

// Infof logs a formatted info message
func (l *SimpleLogger) Infof(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.Info(msg)
}

// Errorf logs a formatted error message
func (l *SimpleLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.Error(msg)
}

// log is the internal logging function
func (l *SimpleLogger) log(level, msg string) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	if l.prefix != "" {
		fmt.Printf("[%s] [%s] [%s] %s\n", timestamp, level, l.prefix, msg)
	} else {
		fmt.Printf("[%s] [%s] %s\n", timestamp, level, msg)
	}
}
