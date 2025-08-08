package log

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/natefinch/lumberjack"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var Logger zerolog.Logger

func InitLogger() {
	const logDir = "logs"
	const logFileName = "app.log"

	// Ensure log directory exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatal().Err(err).Str("path", logDir).Msg("Failed to create log directory")
	}

	// Setup log rotation
	logWriter := &lumberjack.Logger{
		Filename:   filepath.Join(logDir, logFileName),
		MaxSize:    10, // megabytes
		MaxBackups: 5,
		MaxAge:     28, // days
		Compress:   true,
	}

	// Multi-output: console + file
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	multiWriter := io.MultiWriter(output, logWriter)

	zerolog.TimeFieldFormat = time.RFC3339
	Logger = zerolog.New(multiWriter).
		With().
		Timestamp().
		Str("app", "consent-manager").
		Logger()

	// Set global logger for consistency
	log.Logger = Logger
}
