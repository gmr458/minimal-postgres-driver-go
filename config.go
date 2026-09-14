package main

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

// Config holds the connection parameters parsed from a PostgreSQL DSN.
type Config struct {
	Host           string
	User           string
	Password       string
	Database       string
	ConnectTimeout time.Duration
}

// parseDSN parses a PostgreSQL URL into a Config.
//
// It validates the scheme and reads connect_timeout (in seconds),
// falling back to a sane default so a hung/unreachable server
// can't block the client forever.
func parseDSN(dsn string) (Config, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return Config{}, fmt.Errorf("error parsing url: %w", err)
	}

	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return Config{}, fmt.Errorf("incorrect postgresql scheme in the url")
	}

	connectTimeout := 10 * time.Second
	if raw := u.Query().Get("connect_timeout"); raw != "" {
		secs, err := strconv.Atoi(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid connect_timeout %q: %w", raw, err)
		}
		connectTimeout = time.Duration(secs) * time.Second
	}

	password, _ := u.User.Password()

	var database string
	if len(u.Path) > 1 {
		database = u.Path[1:]
	}

	return Config{
		Host:           u.Host,
		User:           u.User.Username(),
		Password:       password,
		Database:       database,
		ConnectTimeout: connectTimeout,
	}, nil
}
