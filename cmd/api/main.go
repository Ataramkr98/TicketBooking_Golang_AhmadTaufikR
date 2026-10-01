package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elysian-premium-lines/backend/internal/cache"
	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/elysian-premium-lines/backend/internal/httpapi"
	"github.com/elysian-premium-lines/backend/internal/provider"
	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/elysian-premium-lines/backend/internal/service"
	"github.com/hibiken/asynq"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// A non-zero status is the only signal an orchestrator gets that the process
	// died rather than was asked to stop, so every failure path returns 1.
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	cancel()
	if err != nil {
		log.Printf("database: %v", err)
		return 1
	}
	defer pool.Close()
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	err = pool.Ping(ctx)
	cancel()
	if err != nil {
		log.Printf("database: %v", err)
		return 1
	}
	var store cache.Store
	if cfg.CacheDriver == "redis" {
		redisStore := cache.NewRedisStore(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
		ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		err = redisStore.Ping(ctx)
		cancel()
		if err != nil {
			log.Printf("redis: %v", err)
			return 1
		}
		store = redisStore
	} else {
		log.Println("warning: CACHE_DRIVER=memory is single-instance development mode")
		store = cache.NewMemoryStore()
	}
	defer store.Close()
	vault, err := security.NewVault(cfg.EncryptionKey, cfg.PIIHashKey)
	if err != nil {
		log.Printf("vault: %v", err)
		return 1
	}
	svc := service.New(cfg, pool, store, vault)
	if cfg.CacheDriver == "redis" {
		notification := provider.NewAsynqNotification(asynq.RedisClientOpt{Addr: cfg.RedisAddr, Password: cfg.RedisPassword, DB: cfg.RedisDB}, vault)
		defer notification.Close()
		svc.UseNotification(notification)
	}
	stopScheduler := make(chan struct{})
	if cfg.CacheDriver == "memory" {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					count, err := svc.ExpireBookings(ctx)
					cancel()
					if err != nil {
						log.Printf("booking expiry error: %v", err)
					} else if count > 0 {
						log.Printf("expired_bookings=%d", count)
					}
				case <-stopScheduler:
					return
				}
			}
		}()
	}
	app := httpapi.New(cfg, svc)
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("elysian api listening on %s", cfg.HTTPAddr)
		serverErr <- app.Listen(cfg.HTTPAddr)
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	exitCode := 0
	select {
	case sig := <-signals:
		log.Printf("received %s, shutting down", sig)
	case err = <-serverErr:
		// app.Listen only returns on a genuine failure (address already in use,
		// socket error) or after Shutdown. Reporting this as "server stopped" and
		// exiting 0 read as a clean shutdown to Docker and Kubernetes, which then
		// treated a crash as a requested stop. The errors.Is(err,
		// context.Canceled) guard that used to sit here was dead code: fasthttp
		// never returns that sentinel.
		log.Printf("http server stopped unexpectedly: %v", err)
		exitCode = 1
	}
	close(stopScheduler)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err = app.ShutdownWithContext(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	return exitCode
}
