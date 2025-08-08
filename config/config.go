package config

import (
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// Server
	Port        string
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
	JWTSecret          string
	PublicKeyPath      string
	PrivateKeyPath     string
	EncryptionKey      string
	DebugAdminSecret   string
	AdminTokenTTL      time.Duration
	AdminRefreshTokenTTL time.Duration
	UserTokenTTL       time.Duration
	UserRefreshTokenTTL time.Duration
}

func LoadConfig() Config {
	_ = godotenv.Load()

	// Parse token TTLs with fallbacks
	adminTTL := mustParseDuration(getEnv("ADMIN_TOKEN_TTL", "1h"))
	adminRefreshTTL := mustParseDuration(getEnv("ADMIN_REFRESH_TOKEN_TTL", "168h")) // 7 days
	userTTL := mustParseDuration(getEnv("USER_TOKEN_TTL", "12h"))
	userRefreshTTL := mustParseDuration(getEnv("USER_REFRESH_TOKEN_TTL", "168h"))   // 7 days

	return Config{
		Port:                getEnv("PORT", "8080"),
		Environment:         getEnv("ENVIRONMENT", "production"),

		DatabaseURL:         getEnv("DATABASE_URL", ""),
		DatabaseUSEastURL:   getEnv("DATABASE_US_EAST", ""),
		DatabaseEUWestURL:   getEnv("DATABASE_EU_WEST", ""),
		DBHost:              getEnv("DB_HOST", "localhost"),
		DBPort:              getEnv("DB_PORT", "5432"),
		DBUser:              getEnv("DB_USER", "postgres"),
		DBPassword:          getEnv("DB_PASSWORD", "postgres"),
		DBName:              getEnv("DB_NAME", "consent_master"),

		JWTSecret:           getEnv("JWT_SECRET", "secret"),
		PublicKeyPath:       getEnv("JWT_PUBLIC_KEY_PATH", "./public.pem"),
		PrivateKeyPath:      getEnv("JWT_PRIVATE_KEY_PATH", "./private.pem"),
		EncryptionKey:       getEnv("ENCRYPTION_KEY", ""),
		DebugAdminSecret:    getEnv("DEBUG_ADMIN_SECRET", ""),

		AdminTokenTTL:       adminTTL,
		AdminRefreshTokenTTL: adminRefreshTTL,
		UserTokenTTL:        userTTL,
		UserRefreshTokenTTL: userRefreshTTL,
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
