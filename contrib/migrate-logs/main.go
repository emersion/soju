package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/irc.v4"

	"codeberg.org/emersion/soju/database"
	"codeberg.org/emersion/soju/msgstore"
	"codeberg.org/emersion/soju/msgstore/znclog"
)

const usage = `usage: migrate-logs <source logs> <destination database>

Migrates existing Soju logs stored on disk to a Soju database. Database is specified
in the format of "driver:source" where driver is sqlite3 or postgres and source
is the string that would be in the Soju config file.

Options:

  -help               Show this help message
`

var logRoot string

func init() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
}

func migrateNetwork(ctx context.Context, db database.Database, user *database.User, network *database.Network) error {
	log.Printf("Migrating logs for network: %s\n", network.GetName())

	rootPath := filepath.Join(logRoot, msgstore.EscapeFilename(user.Username), msgstore.EscapeFilename(network.GetName()))
	root, err := os.Open(rootPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("unable to open network folder: %s", rootPath)
	}

	// The returned targets are escaped, and there is no way to un-escape
	// TODO: switch to ReadDir (Go 1.16+)
	targets, err := root.Readdirnames(0)
	root.Close()
	if err != nil {
		return fmt.Errorf("unable to read network folder: %s", rootPath)
	}

	for _, target := range targets {
		log.Printf("Migrating logs for target: %s\n", target)

		// target is already escaped here
		targetPath := filepath.Join(rootPath, target)
		targetDir, err := os.Open(targetPath)
		if err != nil {
			return fmt.Errorf("unable to open target folder: %s", targetPath)
		}

		entryNames, err := targetDir.Readdirnames(0)
		targetDir.Close()
		if err != nil {
			return fmt.Errorf("unable to read target folder: %s", targetPath)
		}
		sort.Strings(entryNames)

		for _, entryName := range entryNames {
			entryPath := filepath.Join(targetPath, entryName)

			var year, month, day int
			_, err := fmt.Sscanf(entryName, "%04d-%02d-%02d.log", &year, &month, &day)
			if err != nil {
				return fmt.Errorf("invalid entry name: %s", entryName)
			}
			ref := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)

			entry, err := os.Open(entryPath)
			if err != nil {
				return fmt.Errorf("unable to open entry: %s", entryPath)
			}
			sc := bufio.NewScanner(entry)
			var msgs []*irc.Message
			for sc.Scan() {
				msg, _, err := znclog.UnmarshalLine(sc.Text(), user, network, target, ref, true)
				if err != nil {
					return fmt.Errorf("unable to parse entry: %s: %s", entryPath, sc.Text())
				} else if msg == nil {
					continue
				}
				msgs = append(msgs, msg)
			}
			if sc.Err() != nil {
				return fmt.Errorf("unable to parse entry: %s: %v", entryPath, sc.Err())
			}
			_, err = db.StoreMessages(ctx, network.ID, target, msgs)
			if err != nil {
				return fmt.Errorf("unable to store messages: %s: %s: %v", entryPath, sc.Text(), err)
			}
			entry.Close()
		}
	}
	return nil
}

func main() {
	flag.Parse()

	ctx := context.Background()

	logRoot = flag.Arg(0)
	dbParams := strings.SplitN(flag.Arg(1), ":", 2)

	if len(dbParams) != 2 {
		log.Fatalf("database not properly specified: %s", flag.Arg(1))
	}

	db, err := database.Open(dbParams[0], dbParams[1])
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer db.Close()

	users, err := db.ListUsers(ctx)
	if err != nil {
		log.Fatalf("unable to get users: %v", err)
	}

	for _, user := range users {
		log.Printf("Migrating logs for user: %s\n", user.Username)

		networks, err := db.ListNetworks(ctx, user.ID)
		if err != nil {
			log.Fatalf("unable to get networks for user: #%d %s", user.ID, user.Username)
		}

		for _, network := range networks {
			if err := migrateNetwork(ctx, db, &user, &network); err != nil {
				log.Fatalf("migrating %v: %v", network.GetName(), err)
			}
		}
	}
}
