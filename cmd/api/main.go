package main

import (
	"flag"
	"fmt"
	"os"
	"runtime/debug"
	"sync"

	"github.com/Authorie/authorie-backend/internal/env"
	"github.com/Authorie/authorie-backend/internal/leveledlog"
	"github.com/Authorie/authorie-backend/internal/smtp"
	"github.com/Authorie/authorie-backend/internal/version"
)

func main() {
	logger := leveledlog.NewLogger(os.Stdout, leveledlog.LevelAll, true)

	err := run(logger)
	if err != nil {
		trace := debug.Stack()
		logger.Fatal(err, trace)
	}
}

type config struct {
	baseURL  string
	httpPort int
	cookie   struct {
		secretKey string
	}
	notifications struct {
		email string
	}
	smtp struct {
		host     string
		port     int
		username string
		password string
		from     string
	}
}

type application struct {
	config config
	logger *leveledlog.Logger
	mailer *smtp.Mailer
	wg     sync.WaitGroup
}

func run(logger *leveledlog.Logger) error {
	var cfg config

	cfg.baseURL = env.GetString("BASE_URL", "http://localhost:4444")
	cfg.httpPort = env.GetInt("HTTP_PORT", 4444)
	cfg.cookie.secretKey = env.GetString("COOKIE_SECRET_KEY", "ui3uf4igpvtdxyduzlwq2kgvun4u2xio")
	cfg.notifications.email = env.GetString("NOTIFICATIONS_EMAIL", "")
	cfg.smtp.host = env.GetString("SMTP_HOST", "example.smtp.host")
	cfg.smtp.port = env.GetInt("SMTP_PORT", 25)
	cfg.smtp.username = env.GetString("SMTP_USERNAME", "example_username")
	cfg.smtp.password = env.GetString("SMTP_PASSWORD", "pa55word")
	cfg.smtp.from = env.GetString("SMTP_FROM", "Example Name <no_reply@example.org>")

	showVersion := flag.Bool("version", false, "display version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("version: %s\n", version.Get())
		return nil
	}

	mailer := smtp.NewMailer(cfg.smtp.host, cfg.smtp.port, cfg.smtp.username, cfg.smtp.password, cfg.smtp.from)

	app := &application{
		config: cfg,
		logger: logger,
		mailer: mailer,
	}

	return app.serveHTTP()
}
