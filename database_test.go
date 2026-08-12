package main

import (
	"context"
	"os"
	"strings"
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

func TestForeignKeyEnforcementPooledConnection(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() error: %v", err)
	}
	defer db.Close()

	db.SetMaxOpenConns(4)

	_, err = db.Exec("CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
	if err != nil {
		t.Fatalf("create parent table: %v", err)
	}

	_, err = db.Exec("CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER NOT NULL, FOREIGN KEY (parent_id) REFERENCES parent(id))")
	if err != nil {
		t.Fatalf("create child table: %v", err)
	}

	ctx := context.Background()

	conn1, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("db.Conn() error: %v", err)
	}
	defer conn1.Close()

	_, err = db.Exec("INSERT INTO parent (id, name) VALUES (1, 'parent1')")
	if err != nil {
		t.Fatalf("insert parent: %v", err)
	}

	_, err = db.Exec("INSERT INTO child (id, parent_id) VALUES (1, 999)")
	if err == nil {
		t.Fatal("expected foreign key constraint violation, got nil")
	}

	if !strings.Contains(err.Error(), "FOREIGN KEY constraint") {
		t.Fatalf("expected FOREIGN KEY constraint error, got: %v", err)
	}
}

func TestOpenDatabaseDSNSpecialCharacters(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/test file?weird#hash.db"

	db, err := openDatabase(path)
	if err != nil {
		t.Fatalf("openDatabase() with special chars error: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Fatalf("database not reachable: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("database file not found at expected path: %v", err)
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
