package main

import (
	"crypto/sha256"
	"database/sql"
)

type App struct {
	Config         *Config
	DB             *sql.DB
	AdminTokenHash [sha256.Size]byte
}
