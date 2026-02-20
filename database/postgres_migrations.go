package database

var postgresMigrations = []string{
	"", // migration #0 is reserved for schema initialization
	`ALTER TABLE "Network" ALTER COLUMN nick DROP NOT NULL`,
	`
		CREATE TYPE sasl_mechanism AS ENUM ('PLAIN', 'EXTERNAL');
		ALTER TABLE "Network"
			ALTER COLUMN sasl_mechanism
			TYPE sasl_mechanism
			USING sasl_mechanism::sasl_mechanism;
	`,
	`
		CREATE TABLE "ReadReceipt" (
			id SERIAL PRIMARY KEY,
			network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
			target VARCHAR(255) NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			UNIQUE(network, target)
		);
	`,
	`
		CREATE TABLE "WebPushConfig" (
			id SERIAL PRIMARY KEY,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			vapid_key_public TEXT NOT NULL,
			vapid_key_private TEXT NOT NULL,
			UNIQUE(vapid_key_public)
		);

		CREATE TABLE "WebPushSubscription" (
			id SERIAL PRIMARY KEY,
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
			network INTEGER REFERENCES "Network"(id) ON DELETE CASCADE,
			endpoint TEXT NOT NULL,
			key_vapid TEXT,
			key_auth TEXT,
			key_p256dh TEXT,
			UNIQUE(network, endpoint)
		);
	`,
	`
		ALTER TABLE "WebPushSubscription"
		ADD COLUMN "user" INTEGER
		REFERENCES "User"(id) ON DELETE CASCADE
	`,
	`ALTER TABLE "User" ADD COLUMN nick VARCHAR(255)`,
	// Before this migration, a bug swapped user and network, so empty the
	// web push subscriptions table
	`
		DELETE FROM "WebPushSubscription";
		ALTER TABLE "WebPushSubscription"
		ALTER COLUMN "user"
		SET NOT NULL;
	`,
	`ALTER TABLE "Network" ADD COLUMN auto_away BOOLEAN NOT NULL DEFAULT TRUE`,
	`ALTER TABLE "Network" ADD COLUMN certfp TEXT`,
	`ALTER TABLE "User" ADD COLUMN created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()`,
	`ALTER TABLE "User" ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT TRUE`,
	`ALTER TABLE "User" ADD COLUMN downstream_interacted_at TIMESTAMP WITH TIME ZONE`,
	`
		CREATE TABLE "MessageTarget" (
			id SERIAL PRIMARY KEY,
			network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
			target TEXT NOT NULL,
			UNIQUE(network, target)
		);
		CREATE TEXT SEARCH DICTIONARY search_simple_dictionary (
			TEMPLATE = pg_catalog.simple
		);
		CREATE TEXT SEARCH CONFIGURATION @SCHEMA_PREFIX@search_simple ( COPY = pg_catalog.simple );
		ALTER TEXT SEARCH CONFIGURATION @SCHEMA_PREFIX@search_simple ALTER MAPPING FOR asciiword, asciihword, hword_asciipart, hword, hword_part, word WITH @SCHEMA_PREFIX@search_simple_dictionary;
		CREATE TABLE "Message" (
			id SERIAL PRIMARY KEY,
			target INTEGER NOT NULL REFERENCES "MessageTarget"(id) ON DELETE CASCADE,
			raw TEXT NOT NULL,
			time TIMESTAMP WITH TIME ZONE NOT NULL,
			sender TEXT NOT NULL,
			text TEXT,
			text_search tsvector GENERATED ALWAYS AS (to_tsvector('@SCHEMA_PREFIX@search_simple', text)) STORED
		);
		CREATE INDEX "MessageIndex" ON "Message" (target, time);
		CREATE INDEX "MessageSearchIndex" ON "Message" USING GIN (text_search);
	`,
	`ALTER TABLE "User" ADD COLUMN max_networks INTEGER NOT NULL DEFAULT -1`,
	`
		ALTER TABLE "MessageTarget" ADD COLUMN pinned BOOLEAN NOT NULL DEFAULT FALSE;
		ALTER TABLE "MessageTarget" ADD COLUMN muted BOOLEAN NOT NULL DEFAULT FALSE;
	`,
	`
		CREATE INDEX "Network_user_index" ON "Network" ("user");
		CREATE INDEX "Channel_network_index" ON "Channel" (network);
		CREATE INDEX "DeliveryReceipt_network_index" ON "DeliveryReceipt" (network);
		CREATE INDEX "ReadReceipt_network_index" ON "ReadReceipt" (network);
		CREATE INDEX "WebPushSubscription_user_index" ON "WebPushSubscription" ("user");
		CREATE INDEX "WebPushSubscription_network_index" ON "WebPushSubscription" (network);
		CREATE INDEX "MessageTarget_network_index" ON "MessageTarget" (network);
		CREATE INDEX "Message_target_index" ON "MessageTarget" (target);
	`,
	`ALTER TABLE "MessageTarget" ADD COLUMN blocked BOOLEAN NOT NULL DEFAULT FALSE`,
	`
		CREATE TABLE "DeviceCertificate" (
			id SERIAL PRIMARY KEY,
			"user" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
			label TEXT NOT NULL,
			fingerprint BYTEA NOT NULL UNIQUE,
			last_used TIMESTAMP WITH TIME ZONE NOT NULL
		);
	`,
	`ALTER TABLE "DeviceCertificate" ADD COLUMN last_ip TEXT NOT NULL DEFAULT ''`,
}
