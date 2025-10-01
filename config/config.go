package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	Port        string
	AppHost     string
	BaseURL     string
	Environment string // "development", "staging", "production"

	// Database
	DatabaseURL       string
	DatabaseUSEastURL string
	DatabaseEUWestURL string
	DBHost            string
	DBPort            string
	DBUser            string
	DBPassword        string
	DBName            string

	// Security/JWT
	JWTSecret            string
	PublicKeyPath        string
	PrivateKeyPath       string
	EncryptionKey        string
	DebugAdminSecret     string
	AdminTokenTTL        time.Duration
	AdminRefreshTokenTTL time.Duration
	UserTokenTTL         time.Duration
	UserRefreshTokenTTL  time.Duration

	// SMTP
	SMTPHost string
	SMTPPort int
	SMTPUser string
	SMTPPass string

	// External Services
	UIDServiceURL     string
	FrontendBaseURL   string
	DigiLockerBaseURL string
}

func LoadConfig() Config {
	_ = godotenv.Load()

	// HACK: Force database connection to localhost for local development.
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	dbPassword := getEnv("DB_PASSWORD", "root")
	dbName := getEnv("DB_NAME", "master")
	dbURL := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable",
		dbHost,
		dbUser,
		dbPassword,
		dbName,
		dbPort,
	)

	// Parse token TTLs with fallbacks
	adminTTL := mustParseDuration(getEnv("ADMIN_TOKEN_TTL", "1h"))
	adminRefreshTTL := mustParseDuration(getEnv("ADMIN_REFRESH_TOKEN_TTL", "168h")) // 7 days
	userTTL := mustParseDuration(getEnv("USER_TOKEN_TTL", "12h"))
	userRefreshTTL := mustParseDuration(getEnv("USER_REFRESH_TOKEN_TTL", "168h")) // 7 days

	return Config{
		Port:        getEnv("PORT", "8080"),
		AppHost:     getEnv("APP_HOST", "localhost"),
		BaseURL:     getEnv("BASE_URL", "https://localhost:8080"),
		Environment: getEnv("ENVIRONMENT", "production"),

		DatabaseURL:       dbURL,
		DatabaseUSEastURL: getEnv("DATABASE_US_EAST", ""),
		DatabaseEUWestURL: getEnv("DATABASE_EU_WEST", ""),
		DBHost:            getEnv("DB_HOST", "localhost"),
		DBPort:            getEnv("DB_PORT", "5432"),
		DBUser:            getEnv("DB_USER", "postgres"),
		DBPassword:        getEnv("DB_PASSWORD", "postgres"),
		DBName:            getEnv("DB_NAME", "consent_master"),

		JWTSecret:        getEnv("JWT_SECRET", "secret"),
		PublicKeyPath:    getEnv("JWT_PUBLIC_KEY_PATH", "./public.pem"),
		PrivateKeyPath:   getEnv("JWT_PRIVATE_KEY_PATH", "./private.pem"),
		EncryptionKey:    getEnv("ENCRYPTION_KEY", ""),
		DebugAdminSecret: getEnv("DEBUG_ADMIN_SECRET", ""),

		AdminTokenTTL:        adminTTL,
		AdminRefreshTokenTTL: adminRefreshTTL,
		UserTokenTTL:         userTTL,
		UserRefreshTokenTTL:  userRefreshTTL,

		SMTPHost: getEnv("SMTP_HOST", ""),
		SMTPPort: mustParseInt(getEnv("SMTP_PORT", "587")),
		SMTPUser: getEnv("SMTP_USER", ""),
		SMTPPass: getEnv("SMTP_PASS", ""),

		// External Services
		UIDServiceURL:     getEnv("UID_SERVICE_URL", "http://localhost:5001/generate"),
		FrontendBaseURL:   getEnv("FRONTEND_BASE_URL", "http://localhost:5173"),
		DigiLockerBaseURL: getEnv("DIGILOCKER_BASE_URL", "https://digilocker.gov.in"),
	}
}

func getEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

func mustParseDuration(str string) time.Duration {
	d, err := time.ParseDuration(str)
	if err != nil {
		log.Printf("Invalid duration '%s', defaulting to 1h", str)
		return time.Hour
	}
	return d
}

func mustParseInt(str string) int {
	i, err := strconv.Atoi(str)
	if err != nil {
		log.Printf("Invalid integer '%s', defaulting to 0", str)
		return 0
	}
	return i
}
