CREATE TABLE "User" (
	id SERIAL PRIMARY KEY,
	username VARCHAR(255) NOT NULL UNIQUE,
	password VARCHAR(255),
	admin BOOLEAN NOT NULL DEFAULT FALSE,
	nick VARCHAR(255),
	realname VARCHAR(255),
	created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	downstream_interacted_at TIMESTAMP WITH TIME ZONE,
	max_networks INTEGER NOT NULL DEFAULT -1
);

CREATE TYPE sasl_mechanism AS ENUM ('PLAIN', 'EXTERNAL');

CREATE TABLE "Network" (
	id SERIAL PRIMARY KEY,
	name VARCHAR(255),
	"user" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
	addr VARCHAR(255) NOT NULL,
	nick VARCHAR(255),
	username VARCHAR(255),
	realname VARCHAR(255),
	certfp TEXT,
	pass VARCHAR(255),
	connect_commands VARCHAR(1023),
	sasl_mechanism sasl_mechanism,
	sasl_plain_username VARCHAR(255),
	sasl_plain_password VARCHAR(255),
	sasl_external_cert BYTEA,
	sasl_external_key BYTEA,
	auto_away BOOLEAN NOT NULL DEFAULT TRUE,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	UNIQUE("user", addr, nick),
	UNIQUE("user", name)
);

CREATE INDEX "Network_user_index" ON "Network" ("user");

CREATE TABLE "Channel" (
	id SERIAL PRIMARY KEY,
	network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
	name VARCHAR(255) NOT NULL,
	key VARCHAR(255),
	detached BOOLEAN NOT NULL DEFAULT FALSE,
	detached_internal_msgid VARCHAR(255),
	relay_detached INTEGER NOT NULL DEFAULT 0,
	reattach_on INTEGER NOT NULL DEFAULT 0,
	detach_after INTEGER NOT NULL DEFAULT 0,
	detach_on INTEGER NOT NULL DEFAULT 0,
	UNIQUE(network, name)
);

CREATE INDEX "Channel_network_index" ON "Channel" (network);

CREATE TABLE "DeviceCertificate" (
	id SERIAL PRIMARY KEY,
	"user" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
	label TEXT NOT NULL,
	fingerprint BYTEA NOT NULL UNIQUE,
	last_used TIMESTAMP WITH TIME ZONE NOT NULL,
	last_ip TEXT NOT NULL
);

CREATE TABLE "DeliveryReceipt" (
	id SERIAL PRIMARY KEY,
	network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
	target VARCHAR(255) NOT NULL,
	client VARCHAR(255) NOT NULL DEFAULT '',
	internal_msgid VARCHAR(255) NOT NULL,
	UNIQUE(network, target, client)
);

CREATE INDEX "DeliveryReceipt_network_index" ON "DeliveryReceipt" (network);

CREATE TABLE "ReadReceipt" (
	id SERIAL PRIMARY KEY,
	network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
	target VARCHAR(255) NOT NULL,
	timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
	UNIQUE(network, target)
);

CREATE INDEX "ReadReceipt_network_index" ON "ReadReceipt" (network);

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
	"user" INTEGER NOT NULL REFERENCES "User"(id) ON DELETE CASCADE,
	network INTEGER REFERENCES "Network"(id) ON DELETE CASCADE,
	endpoint TEXT NOT NULL,
	key_vapid TEXT,
	key_auth TEXT,
	key_p256dh TEXT,
	UNIQUE(network, endpoint)
);

CREATE INDEX "WebPushSubscription_user_index" ON "WebPushSubscription" ("user");
CREATE INDEX "WebPushSubscription_network_index" ON "WebPushSubscription" (network);

CREATE TABLE "MessageTarget" (
	id SERIAL PRIMARY KEY,
	network INTEGER NOT NULL REFERENCES "Network"(id) ON DELETE CASCADE,
	target TEXT NOT NULL,
	pinned BOOLEAN NOT NULL DEFAULT FALSE,
	muted BOOLEAN NOT NULL DEFAULT FALSE,
	blocked BOOLEAN NOT NULL DEFAULT FALSE,
	UNIQUE(network, target)
);

CREATE INDEX "MessageTarget_network_index" ON "MessageTarget" (network);

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
CREATE INDEX "Message_target_index" ON "MessageTarget" (target);
CREATE INDEX "MessageSearchIndex" ON "Message" USING GIN (text_search);
