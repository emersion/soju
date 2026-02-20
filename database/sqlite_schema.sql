CREATE TABLE User (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password TEXT,
	admin INTEGER NOT NULL DEFAULT 0,
	realname TEXT,
	nick TEXT,
	created_at TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	downstream_interacted_at TEXT,
	max_networks INTEGER NOT NULL DEFAULT -1
);

CREATE TABLE Network (
	id INTEGER PRIMARY KEY,
	name TEXT,
	user INTEGER NOT NULL,
	addr TEXT NOT NULL,
	nick TEXT,
	username TEXT,
	realname TEXT,
	certfp TEXT,
	pass TEXT,
	connect_commands TEXT,
	sasl_mechanism TEXT,
	sasl_plain_username TEXT,
	sasl_plain_password TEXT,
	sasl_external_cert BLOB,
	sasl_external_key BLOB,
	auto_away INTEGER NOT NULL DEFAULT 1,
	enabled INTEGER NOT NULL DEFAULT 1,
	FOREIGN KEY(user) REFERENCES User(id),
	UNIQUE(user, addr, nick),
	UNIQUE(user, name)
);

CREATE INDEX Network_user_index ON Network(user);

CREATE TABLE Channel (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	name TEXT NOT NULL,
	key TEXT,
	detached INTEGER NOT NULL DEFAULT 0,
	detached_internal_msgid TEXT,
	relay_detached INTEGER NOT NULL DEFAULT 0,
	reattach_on INTEGER NOT NULL DEFAULT 0,
	detach_after INTEGER NOT NULL DEFAULT 0,
	detach_on INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, name)
);

CREATE INDEX Channel_network_index ON Channel(network);

CREATE TABLE DeviceCertificate (
	id INTEGER PRIMARY KEY,
	user INTEGER NOT NULL,
	label TEXT NOT NULL,
	fingerprint BLOB NOT NULL UNIQUE,
	last_used TEXT NOT NULL,
	last_ip TEXT NOT NULL,
	FOREIGN KEY(user) REFERENCES User(id)
);

CREATE TABLE DeliveryReceipt (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	target TEXT NOT NULL,
	client TEXT,
	internal_msgid TEXT NOT NULL,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, target, client)
);

CREATE INDEX DeliveryReceipt_network_index ON DeliveryReceipt(network);

CREATE TABLE ReadReceipt (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	target TEXT NOT NULL,
	timestamp TEXT NOT NULL,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, target)
);

CREATE INDEX ReadReceipt_network_index ON ReadReceipt(network);

CREATE TABLE WebPushConfig (
	id INTEGER PRIMARY KEY,
	created_at TEXT NOT NULL,
	vapid_key_public TEXT NOT NULL,
	vapid_key_private TEXT NOT NULL,
	UNIQUE(vapid_key_public)
);

CREATE TABLE WebPushSubscription (
	id INTEGER PRIMARY KEY,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	user INTEGER NOT NULL,
	network INTEGER,
	endpoint TEXT NOT NULL,
	key_vapid TEXT,
	key_auth TEXT,
	key_p256dh TEXT,
	FOREIGN KEY(user) REFERENCES User(id),
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, endpoint)
);

CREATE INDEX WebPushSubscription_user_index ON WebPushSubscription(user);
CREATE INDEX WebPushSubscription_network_index ON WebPushSubscription(network);

CREATE TABLE Message (
	id INTEGER PRIMARY KEY,
	target INTEGER NOT NULL,
	raw TEXT NOT NULL,
	time TEXT NOT NULL,
	sender TEXT NOT NULL,
	text TEXT,
	FOREIGN KEY(target) REFERENCES MessageTarget(id)
);

CREATE INDEX MessageIndex ON Message(target, time);
CREATE INDEX Message_target_index ON Message(target);

CREATE TABLE MessageTarget (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	target TEXT NOT NULL,
	pinned INTEGER NOT NULL DEFAULT 0,
	muted INTEGER NOT NULL DEFAULT 0,
	blocked INTEGER NOT NULL DEFAULT 0,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, target)
);

CREATE INDEX MessageTarget_network_index ON MessageTarget(network);

CREATE VIRTUAL TABLE MessageFTS USING fts5 (
	text,
	content=Message,
	content_rowid=id
);
CREATE TRIGGER MessageFTSInsert AFTER INSERT ON Message BEGIN
	INSERT INTO MessageFTS(rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER MessageFTSDelete AFTER DELETE ON Message BEGIN
	INSERT INTO MessageFTS(MessageFTS, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TRIGGER MessageFTSUpdate AFTER UPDATE ON Message BEGIN
	INSERT INTO MessageFTS(MessageFTS, rowid, text) VALUES ('delete', old.id, old.text);
	INSERT INTO MessageFTS(rowid, text) VALUES (new.id, new.text);
END;
