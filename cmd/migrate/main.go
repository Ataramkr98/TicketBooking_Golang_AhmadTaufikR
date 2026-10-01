package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

type migrationFile struct {
	version   int64
	direction string
	path      string
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	direction := "up"
	if len(os.Args) > 1 {
		direction = os.Args[1]
	}
	if direction != "up" && direction != "down" {
		log.Fatal("usage: go run ./cmd/migrate [up|down]")
	}

	migrationsDir := filepath.Join("database", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		log.Fatalf("read migrations dir: %v", err)
	}

	var files []migrationFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		parts := strings.Split(name, ".")
		if len(parts) < 3 {
			continue
		}
		dir := parts[len(parts)-2]
		if dir != direction {
			continue
		}
		numPart := strings.Split(parts[0], "_")[0]
		ver, err := strconv.ParseInt(numPart, 10, 64)
		if err != nil {
			continue
		}
		files = append(files, migrationFile{
			version:   ver,
			direction: dir,
			path:      filepath.Join(migrationsDir, name),
		})
	}

	sort.Slice(files, func(i, j int) bool {
		if direction == "up" {
			return files[i].version < files[j].version
		}
		return files[i].version > files[j].version
	})

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	if _, err = pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations(version bigint PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		log.Fatal(err)
	}

	appliedMap := make(map[int64]bool)
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		var ver int64
		if err := rows.Scan(&ver); err == nil {
			appliedMap[ver] = true
		}
	}
	rows.Close()

	appliedCount := 0
	for _, f := range files {
		isApplied := appliedMap[f.version]
		if direction == "up" && isApplied {
			continue
		}
		if direction == "down" && !isApplied {
			continue
		}

		sql, err := os.ReadFile(f.path)
		if err != nil {
			log.Fatalf("read migration %s: %v", f.path, err)
		}
		// Strip UTF-8 BOM if present
		if len(sql) >= 3 && sql[0] == 0xef && sql[1] == 0xbb && sql[2] == 0xbf {
			sql = sql[3:]
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			log.Fatal(err)
		}
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			tx.Rollback(ctx)
			log.Fatalf("exec migration %s: %v", f.path, err)
		}

		if direction == "up" {
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, f.version)
		} else {
			_, err = tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=$1`, f.version)
		}
		if err != nil {
			tx.Rollback(ctx)
			log.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			log.Fatal(err)
		}
		appliedCount++
		fmt.Printf("migration %s (%d) applied successfully\n", filepath.Base(f.path), f.version)
	}

	if appliedCount == 0 {
		fmt.Println("no pending migrations to apply")
	}
}
