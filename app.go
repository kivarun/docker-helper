package main

import "database/sql"

type App struct {
	Config *Config
	DB     *sql.DB
}
