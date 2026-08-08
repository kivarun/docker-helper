package main

import (
	"crypto/sha256"
	"database/sql"
	"io"
	"log/slog"
)

type App struct {
	Config         *Config
	DB             *sql.DB
	AdminTokenHash [sha256.Size]byte
	AuditWriter    io.Writer
	OpLogger       *slog.Logger
	RunCommand     func(string, ...string) ([]byte, error)
	BuildCommand   func(string, ...string) ([]byte, error)
	PullCommand    func(string, ...string) ([]byte, error)
}
