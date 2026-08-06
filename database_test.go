package main

import (
	"os"
	"testing"
)

func TestOpenDatabase(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Errorf("database not reachable after open: %v", err)
	}
}

func TestInitializeDatabase(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}
}

func TestSessionsTableExists(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='sessions';").Scan(&name)
	if err != nil {
		t.Fatalf("sessions table not found: %v", err)
	}

	if name != "sessions" {
		t.Errorf("expected table name 'sessions', got %q", name)
	}
}

func TestInitializeDatabaseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("first initializeDatabase() error: %v", err)
	}

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("second initializeDatabase() error: %v", err)
	}
}

func TestJournalModeWAL(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	var mode string
	err = db.QueryRow("PRAGMA journal_mode;").Scan(&mode)
	if err != nil {
		t.Fatalf("cannot query journal_mode: %v", err)
	}

	if mode != "wal" {
		t.Errorf("expected journal_mode 'wal', got %q", mode)
	}
}

func TestForeignKeysEnabled(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	var enabled int
	err = db.QueryRow("PRAGMA foreign_keys;").Scan(&enabled)
	if err != nil {
		t.Fatalf("cannot query foreign_keys: %v", err)
	}

	if enabled != 1 {
		t.Errorf("expected foreign_keys enabled (1), got %d", enabled)
	}
}

func TestDatabaseClose(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}

	if err := initializeDatabase(db); err != nil {
		t.Fatalf("initializeDatabase() error: %v", err)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("db.Close() error: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file should exist after close: %v", err)
	}
}
