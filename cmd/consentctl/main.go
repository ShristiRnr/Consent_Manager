package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/urfave/cli/v2"
)

func run(name string, args []string, background bool) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if background {
		if err := cmd.Start(); err != nil {
			log.Printf("❌ Failed to start %s: %v", name, err)
		} else {
			log.Printf("✅ %s started in background (PID %d)", name, cmd.Process.Pid)
		}
		return
	}

	log.Printf("▶️ Running: %s", name)
	if err := cmd.Run(); err != nil {
		log.Fatalf("❌ %s failed: %v", name, err)
	}
}

func main() {
	app := &cli.App{
		Name:  "consentctl",
		Usage: "Consent Manager CLI for local dev tasks",
		Commands: []*cli.Command{
			{
				Name:  "genkey",
				Usage: "Generate API key and hash",
				Action: func(c *cli.Context) error {
					run("genkey", []string{"go", "run", "./cmd/genkey"}, false)
					return nil
				},
			},
			{
				Name:  "migrate",
				Usage: "Run DB migration for default values",
				Action: func(c *cli.Context) error {
					run("migrate", []string{"go", "run", "./cmd/migrate"}, false)
					return nil
				},
			},
			{
				Name:  "retry",
				Usage: "Start retry worker (webhook DLQ)",
				Action: func(c *cli.Context) error {
					run("retry-worker", []string{"go", "run", "./cmd/retry"}, false)
					return nil
				},
			},
			{
				Name:  "server",
				Usage: "Start main API server",
				Action: func(c *cli.Context) error {
					run("server", []string{"go", "run", "./cmd/server"}, false)
					return nil
				},
			},
			{
				Name:  "setup-tenant",
				Usage: "Create a new tenant and schema",
				Action: func(c *cli.Context) error {
					run("setup-tenant", []string{"go", "run", "./cmd/setup-tenant"}, false)
					return nil
				},
			},
			{
				Name:  "genrsa",
				Usage: "Generate RSA keys",
				Action: func(c *cli.Context) error {
					run("genrsa", []string{"go", "run", "./cmd/genrsa"}, false)
					return nil
				},
			},
			{
				Name:  "all",
				Usage: "Run everything sequentially (except server)",
				Action: func(c *cli.Context) error {
					run("genkey", []string{"go", "run", "./cmd/genkey"}, false)
					time.Sleep(time.Second)
					run("genrsa", []string{"go", "run", "./cmd/genrsa"}, false)
					time.Sleep(time.Second)
					run("migrate", []string{"go", "run", "./cmd/migrate"}, false)
					// time.Sleep(time.Second)
					// run("setup-tenant", []string{"go", "run", "./cmd/setup-tenant"}, false)
					time.Sleep(time.Second)
					run("retry-worker", []string{"go", "run", "./cmd/retry"}, true)
					time.Sleep(time.Second)
					fmt.Println("🚀 Use `consentctl server` to launch the API server.")
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
