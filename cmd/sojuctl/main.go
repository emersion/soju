package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"

	"git.sr.ht/~emersion/soju/config"
	"git.sr.ht/~emersion/soju/database"
)

const usage = `usage: sojuctl [-config path] <action> [options...]

  create-user <username> [-admin]  Create a new user
  change-password <username>       Change password for a user
  help                             Show this help message
`

func init() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage)
	}
}

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", config.DefaultPath, "path to configuration file")
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

	db, err := database.Open(cfg.DB.Driver, cfg.DB.Source)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	ctx := context.Background()

	switch cmd := flag.Arg(0); cmd {
	case "create-user":
		username := flag.Arg(1)
		if username == "" {
			flag.Usage()
			os.Exit(1)
		}

		fs := flag.NewFlagSet("", flag.ExitOnError)
		admin := fs.Bool("admin", false, "make the new user admin")
		fs.Parse(flag.Args()[2:])

		password, err := readPassword()
		if err != nil {
			log.Fatalf("failed to read password: %v", err)
		}

		hashed, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("failed to hash password: %v", err)
		}

		user := database.User{
			Username: username,
			Password: string(hashed),
			Admin:    *admin,
			Enabled:  true,
		}
		if err := db.StoreUser(ctx, &user); err != nil {
			log.Fatalf("failed to create user: %v", err)
		}
	case "change-password":
		username := flag.Arg(1)
		if username == "" {
			flag.Usage()
			os.Exit(1)
		}

		user, err := db.GetUser(ctx, username)
		if err != nil {
			log.Fatalf("failed to get user: %v", err)
		}

		password, err := readPassword()
		if err != nil {
			log.Fatalf("failed to read password: %v", err)
		}

		hashed, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("failed to hash password: %v", err)
		}

		user.Password = string(hashed)
		if err := db.StoreUser(ctx, user); err != nil {
			log.Fatalf("failed to update password: %v", err)
		}
	default:
		flag.Usage()
		if cmd != "help" {
			os.Exit(1)
		}
	}
}

func readPassword() ([]byte, error) {
	var password []byte
	var err error
	fd := int(os.Stdin.Fd())

	if terminal.IsTerminal(fd) {
		fmt.Printf("Password: ")
		password, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Printf("\n")
	} else {
		fmt.Fprintf(os.Stderr, "Warning: Reading password from stdin.\n")
		// TODO: the buffering messes up repeated calls to readPassword
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return nil, err
			}
			return nil, io.ErrUnexpectedEOF
		}
		password = scanner.Bytes()

		if len(password) == 0 {
			return nil, fmt.Errorf("zero length password")
		}
	}

	return password, nil
}
