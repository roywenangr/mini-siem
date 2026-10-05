// Command siem runs the Mini SIEM server: log inputs, detection engine,
// storage, REST API and dashboard in one binary.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/roywenangr/mini-siem/internal/api"
	"github.com/roywenangr/mini-siem/internal/ingest"
	"github.com/roywenangr/mini-siem/internal/intel"
	"github.com/roywenangr/mini-siem/internal/parser"
	"github.com/roywenangr/mini-siem/internal/pipeline"
	"github.com/roywenangr/mini-siem/internal/rules"
	"github.com/roywenangr/mini-siem/internal/sigma"
	"github.com/roywenangr/mini-siem/internal/store"
)

// Config is the YAML configuration file.
type Config struct {
	Listen    string        `yaml:"listen"`
	DB        string        `yaml:"db"`
	Rules     string        `yaml:"rules"`
	AuthToken string        `yaml:"auth_token"`
	Retention time.Duration `yaml:"retention"`
	Inputs    []Input       `yaml:"inputs"`
	Webhook   struct {
		URL         string `yaml:"url"`
		MinSeverity string `yaml:"min_severity"`
	} `yaml:"webhook"`
	Sigma struct {
		Paths        []string      `yaml:"paths"`
		MinLevel     string        `yaml:"min_level"`
		IncludeProxy bool          `yaml:"include_proxy"`
		DedupWindow  time.Duration `yaml:"dedup_window"`
	} `yaml:"sigma"`
	ThreatIntel struct {
		Refresh time.Duration `yaml:"refresh"`
		Feeds   []intel.Feed  `yaml:"feeds"`
	} `yaml:"threat_intel"`
	LogLevel string `yaml:"log_level"`
}

// Input is a log file to tail.
type Input struct {
	Path      string `yaml:"path"`
	Parser    string `yaml:"parser"`
	FromStart bool   `yaml:"from_start"`
}

func defaults() Config {
	return Config{
		Listen:    "127.0.0.1:8080",
		DB:        "data/siem.db",
		Rules:     "rules/default.yaml",
		Retention: 7 * 24 * time.Hour,
		LogLevel:  "info",
	}
}

func loadConfig(path string) (Config, error) {
	cfg := defaults()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "siem:", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to config YAML (optional)")
	listen := flag.String("listen", "", "override listen address")
	dbPath := flag.String("db", "", "override database path")
	rulesPath := flag.String("rules", "", "override rules file")
	sigmaPaths := flag.String("sigma", "", "comma-separated Sigma rule files or directories to load (adds to config)")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if *dbPath != "" {
		cfg.DB = *dbPath
	}
	if *rulesPath != "" {
		cfg.Rules = *rulesPath
	}
	if *sigmaPaths != "" {
		cfg.Sigma.Paths = append(cfg.Sigma.Paths, strings.Split(*sigmaPaths, ",")...)
	}
	if tok := os.Getenv("SIEM_TOKEN"); tok != "" {
		cfg.AuthToken = tok
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("log_level: %w", err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	rs, err := rules.LoadFile(cfg.Rules)
	if err != nil {
		return err
	}
	log.Info("rules loaded", "file", cfg.Rules, "count", len(rs))

	var sigmaReport *sigma.Report
	if len(cfg.Sigma.Paths) > 0 {
		srs, rep, err := sigma.LoadPaths(cfg.Sigma.Paths, sigma.Options{
			DedupWindow:  cfg.Sigma.DedupWindow,
			MinLevel:     cfg.Sigma.MinLevel,
			IncludeProxy: cfg.Sigma.IncludeProxy,
		})
		if err != nil {
			return err
		}
		for _, e := range rep.Errors {
			log.Warn("sigma rule skipped", "err", e)
		}
		log.Info("sigma rules loaded", "loaded", rep.Loaded, "files", rep.Files, "skipped", rep.Skipped)
		rs = append(rs, srs...)
		sigmaReport = rep
	}

	if dir := filepath.Dir(cfg.DB); dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	st, err := store.Open(cfg.DB)
	if err != nil {
		return err
	}
	defer st.Close()

	var notifiers []pipeline.Notifier
	if cfg.Webhook.URL != "" {
		wh, err := pipeline.NewWebhook(cfg.Webhook.URL, cfg.Webhook.MinSeverity, log)
		if err != nil {
			return err
		}
		notifiers = append(notifiers, wh)
		log.Info("webhook notifications enabled", "min_severity", cfg.Webhook.MinSeverity)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var ti *intel.Intel
	var enrichers []pipeline.Enricher
	if len(cfg.ThreatIntel.Feeds) > 0 {
		if ti, err = intel.New(cfg.ThreatIntel.Feeds, log); err != nil {
			return err
		}
		// Load once before ingesting so the first events are already
		// checked, then keep refreshing in the background.
		ti.Refresh(ctx)
		refresh := cfg.ThreatIntel.Refresh
		if refresh == 0 {
			refresh = 6 * time.Hour
		}
		go ti.Run(ctx, refresh)
		enrichers = append(enrichers, ti)
	}

	engine := rules.NewEngine(rs)
	hub := pipeline.NewHub()
	pipe := pipeline.New(st, engine, hub, log, pipeline.Options{Retention: cfg.Retention, Enrichers: enrichers}, notifiers...)

	var wg sync.WaitGroup
	pipeCtx, stopPipe := context.WithCancel(context.Background())
	defer stopPipe()
	pipeDone := make(chan struct{})
	go func() { pipe.Run(pipeCtx); close(pipeDone) }()

	for _, in := range cfg.Inputs {
		p, err := parser.Get(in.Parser)
		if err != nil {
			return fmt.Errorf("input %s: %w", in.Path, err)
		}
		t := &ingest.Tailer{Path: in.Path, Parser: p, FromStart: in.FromStart, Out: pipe, Log: log}
		wg.Add(1)
		go func() { defer wg.Done(); t.Run(ctx) }()
	}

	if cfg.AuthToken == "" && !isLoopback(cfg.Listen) {
		log.Warn("listening on a non-loopback address without auth_token; anyone who can reach it can read your logs")
	}

	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: (&api.Server{
			Store: st, Pipeline: pipe, Engine: engine, Hub: hub,
			Intel: ti, SigmaReport: sigmaReport,
			Token: cfg.AuthToken, Log: log,
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("dashboard ready", "url", "http://"+cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		stop()
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Close the hub first so open dashboard streams end and Shutdown can
	// finish, then stop inputs, then let the pipeline drain its queue.
	hub.Close()
	_ = srv.Shutdown(shutdownCtx)
	wg.Wait()
	stopPipe()
	<-pipeDone
	return nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
