package main

import (
	"log/slog"
	"os"
)

const defaultDSN = "postgresql://postgres:password123@127.0.0.1:5432/dvdrental?sslmode=require&application_name=myapp&connect_timeout=10"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: false}))

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = defaultDSN
	}

	if err := run(dsn, logger); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
