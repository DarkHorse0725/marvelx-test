package utils

import (
	"log"
	"time"
)

func logWithLevel(level string, tag string, msg string, args ...interface{}) {
	prefix := time.Now().Format("2006-01-02 15:04:05") + " [" + level + "]"
	if tag != "" {
		prefix += " [" + tag + "]"
	}
	log.Printf(prefix+" "+msg, args...)
}

func Info(tag string, msg string, args ...interface{}) {
	logWithLevel("INFO", tag, msg, args...)
}

func Warn(tag string, msg string, args ...interface{}) {
	logWithLevel("WARN", tag, msg, args...)
}

func Error(tag string, msg string, args ...interface{}) {
	logWithLevel("ERROR", tag, msg, args...)
}
