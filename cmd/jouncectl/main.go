package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"git.sr.ht/~emersion/jounce"
	"git.sr.ht/~emersion/jounce/config"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

const usage = `usage: jouncectl [-config path] <action> [options...]

  create-user <username>  Create a new user
  help                    Show this help message
`

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage)
	}
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "path to configuration file")
	flag.Parse()

	var cfg *config.Server
	if configPath != "" {
		var err error
		cfg, err = config.Load(configPath)
		if err != nil {
			log.Fatalf("failed to load config file: %v", err)
		}
	} else {
		cfg = config.Defaults()
	}

	db, err := jounce.OpenSQLDB(cfg.SQLDriver, cfg.SQLSource)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	switch cmd := flag.Arg(0); cmd {
	case "create-user":
		username := flag.Arg(1)
		if username == "" {
			flag.Usage()
			os.Exit(1)
		}

		fmt.Printf("Password: ")
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("failed to read password: %v", err)
		}
		fmt.Printf("\n")

		hashed, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("failed to hash password: %v", err)
		}

		user := jounce.User{
			Username: username,
			Password: string(hashed),
		}
		if err := db.CreateUser(&user); err != nil {
			log.Fatalf("failed to create user: %v", err)
		}
	default:
		flag.Usage()
		if cmd != "help" {
			os.Exit(1)
		}
	}
}
