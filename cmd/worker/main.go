package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elysian-premium-lines/backend/internal/cache"
	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/elysian-premium-lines/backend/internal/provider"
	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/elysian-premium-lines/backend/internal/service"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
)

const expireTask = "booking:expire"

func main() {
	// A worker that dies on a bad DSN or an unreachable Redis has to say so
	// through its exit status, not only through a log line nobody is watching.
	if code := run(); code != 0 {
		os.Exit(code)
	}
}

func run() int {
	cfg, err := config.Load()
	if err != nil {
		log.Printf("config: %v", err)
		return 1
	}
	if cfg.CacheDriver != "redis" {
		log.Fatal("worker requires CACHE_DRIVER=redis; memory mode runs scheduler inside API")
	}
	// Both dependencies are verified before the worker accepts work. Without the
	// pings it started happily with a broken DSN, took no tasks, and reported
	// itself as healthy.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		cancel()
		log.Printf("database: %v", err)
		return 1
	}
	err = pool.Ping(ctx)
	cancel()
	if err != nil {
		pool.Close()
		log.Printf("database: %v", err)
		return 1
	}
	defer pool.Close()

	store := cache.NewRedisStore(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	defer store.Close()
	pingCtx, pingCancel := context.WithTimeout(context.Background(), 3*time.Second)
	err = store.Ping(pingCtx)
	pingCancel()
	if err != nil {
		log.Printf("redis: %v", err)
		return 1
	}

	vault, err := security.NewVault(cfg.EncryptionKey, cfg.PIIHashKey)
	if err != nil {
		log.Printf("vault: %v", err)
		return 1
	}
	svc := service.New(cfg, pool, store, vault)
	redisOpt := asynq.RedisClientOpt{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB}
	scheduler := asynq.NewScheduler(redisOpt, nil)
	if _, err = scheduler.Register("* * * * *", asynq.NewTask(expireTask, nil), asynq.Unique(50*time.Second)); err != nil {
		log.Printf("scheduler: %v", err)
		return 1
	}
	// The scheduler error travels to main instead of calling log.Fatal from a
	// goroutine, which would abort the process and skip every deferred Close.
	schedulerErr := make(chan error, 1)
	go func() { schedulerErr <- scheduler.Run() }()

	server := asynq.NewServer(redisOpt, asynq.Config{Concurrency: 4, Queues: map[string]int{"critical": 2, "default": 1}})
	mux := asynq.NewServeMux()
	mux.HandleFunc(expireTask, func(ctx context.Context, task *asynq.Task) error {
		count, err := svc.ExpireBookings(ctx)
		if err == nil && count > 0 {
			payload, _ := json.Marshal(map[string]int64{"expired": count})
			log.Printf("task=%s payload=%s", expireTask, payload)
		}
		return err
	})
	mux.HandleFunc(provider.NotificationOTPTask, func(ctx context.Context, task *asynq.Task) error {
		payload, err := provider.DecodeOTPNotification(vault, task.Payload())
		if err != nil {
			return err
		}
		return provider.NewLogNotification().SendOTP(ctx, payload.Phone, payload.Code)
	})
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Run(mux) }()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	exitCode := 0
	select {
	case sig := <-signals:
		log.Printf("received %s, shutting down", sig)
		scheduler.Shutdown()
		server.Shutdown()
	case err = <-serverErr:
		scheduler.Shutdown()
		log.Printf("asynq server stopped unexpectedly: %v", err)
		exitCode = 1
	case err = <-schedulerErr:
		server.Shutdown()
		log.Printf("asynq scheduler stopped unexpectedly: %v", err)
		exitCode = 1
	}
	// Both Run calls return once their Shutdown has drained, so the deferred
	// Close of the pool, the store, and the vault only runs after the work is
	// finished.
	return exitCode
}
