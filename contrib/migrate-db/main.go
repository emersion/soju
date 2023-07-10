package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"

	"git.sr.ht/~emersion/soju/database"
)

const usage = `usage: migrate-db <source database> <destination database>

Migrates an existing Soju database to another system. Database is specified
in the format of "driver:source" where driver is sqlite3 or postgres and source
is the string that would be in the Soju config file.

Options:

  -help               Show this help message
`

func init() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
	}
}

func main() {
	flag.Parse()

	ctx := context.Background()

	source := strings.Split(flag.Arg(0), ":")
	destination := strings.Split(flag.Arg(1), ":")

	if len(source) != 2 || len(destination) != 2 {
		log.Fatalf("source or destination not properly specified: %s %s", flag.Arg(0), flag.Arg(1))
	}

	sourcedb, err := database.Open(source[0], source[1])
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer sourcedb.Close()

	destinationdb, err := database.Open(destination[0], destination[1])
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer destinationdb.Close()

	users, err := sourcedb.ListUsers(ctx)
	if err != nil {
		log.Fatal("unable to get source users")
	}

	for _, user := range users {
		log.Printf("Storing user: %s\n", user.Username)

		user.ID = 0

		err := destinationdb.StoreUser(ctx, &user)
		if err != nil {
			log.Fatalf("unable to store user: #%d %s", user.ID, user.Username)
		}

		networks, err := sourcedb.ListNetworks(ctx, user.ID)
		if err != nil {
			log.Fatalf("unable to get source networks for user: #%d %s", user.ID, user.Username)
		}

		for _, srcNetwork := range networks {
			log.Printf("Storing network: %s\n", srcNetwork.Name)
			destNetwork := srcNetwork

			destNetwork.ID = 0

			err := destinationdb.StoreNetwork(ctx, user.ID, &destNetwork)
			if err != nil {
				log.Fatalf("unable to store network: #%d %s", srcNetwork.ID, srcNetwork.Name)
			}

			channels, err := sourcedb.ListChannels(ctx, srcNetwork.ID)
			if err != nil {
				log.Fatalf("unable to get source channels for network: #%d %s", srcNetwork.ID, srcNetwork.Name)
			}

			for _, channel := range channels {
				log.Printf("Storing channel: %s\n", channel.Name)

				channel.ID = 0

				err := destinationdb.StoreChannel(ctx, destNetwork.ID, &channel)
				if err != nil {
					log.Fatalf("unable to store channel: #%d %s", channel.ID, channel.Name)
				}
			}

			deliveryReceipts, err := sourcedb.ListDeliveryReceipts(ctx, srcNetwork.ID)
			if err != nil {
				log.Fatalf("unable to get source delivery receipts for network: #%d %s", srcNetwork.ID, srcNetwork.Name)
			}

			drcpts := make(map[string][]database.DeliveryReceipt)

			for _, d := range deliveryReceipts {
				if drcpts[d.Client] == nil {
					drcpts[d.Client] = make([]database.DeliveryReceipt, 0)
				}

				d.ID = 0

				drcpts[d.Client] = append(drcpts[d.Client], d)
			}

			for client, rcpts := range drcpts {
				log.Printf("Storing delivery receipt for: %s.%s.%s", user.Username, srcNetwork.Name, client)
				err := destinationdb.StoreClientDeliveryReceipts(ctx, destNetwork.ID, client, rcpts)
				if err != nil {
					log.Fatalf("unable to store delivery receipts for network and client: %s %s", srcNetwork.Name, client)
				}
			}

			// TODO: migrate read receipts as well

			webPushSubscriptions, err := sourcedb.ListWebPushSubscriptions(ctx, user.ID, srcNetwork.ID)
			if err != nil {
				log.Fatalf("unable to get source web push subscriptions for user and network: %s %s", user.Username, srcNetwork.Name)
			}

			for _, sub := range webPushSubscriptions {
				log.Printf("Storing web push subscription: %s.%s.%d", user.Username, srcNetwork.Name, sub.ID)

				sub.ID = 0

				err := destinationdb.StoreWebPushSubscription(ctx, user.ID, destNetwork.ID, &sub)
				if err != nil {
					log.Fatalf("unable to store web push subscription for user and network: %s %s", user.Username, srcNetwork.Name)
				}
			}
		}
	}

	webPushConfigs, err := sourcedb.ListWebPushConfigs(ctx)
	if err != nil {
		log.Fatal("unable to get source web push configs")
	}

	for _, config := range webPushConfigs {
		log.Printf("Storing web push config: %d", config.ID)
		config.ID = 0
		err := destinationdb.StoreWebPushConfig(ctx, &config)
		if err != nil {
			log.Fatalf("unable to store web push config: #%d", config.ID)
		}
	}
}
