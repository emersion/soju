//go:build !nosqlite

package database

var sqliteMigrations = []string{
	"", // migration #0 is reserved for schema initialization
	"ALTER TABLE Network ADD COLUMN connect_commands VARCHAR(1023)",
	"ALTER TABLE Channel ADD COLUMN detached INTEGER NOT NULL DEFAULT 0",
	"ALTER TABLE Network ADD COLUMN sasl_external_cert BLOB DEFAULT NULL",
	"ALTER TABLE Network ADD COLUMN sasl_external_key BLOB DEFAULT NULL",
	"ALTER TABLE User ADD COLUMN admin INTEGER NOT NULL DEFAULT 0",
	`
		CREATE TABLE UserNew (
			id INTEGER PRIMARY KEY,
			username VARCHAR(255) NOT NULL UNIQUE,
			password VARCHAR(255),
			admin INTEGER NOT NULL DEFAULT 0
		);
		INSERT INTO UserNew SELECT rowid, username, password, admin FROM User;
		DROP TABLE User;
		ALTER TABLE UserNew RENAME TO User;
	`,
	`
		CREATE TABLE NetworkNew (
			id INTEGER PRIMARY KEY,
			name VARCHAR(255),
			user INTEGER NOT NULL,
			addr VARCHAR(255) NOT NULL,
			nick VARCHAR(255) NOT NULL,
			username VARCHAR(255),
			realname VARCHAR(255),
			pass VARCHAR(255),
			connect_commands VARCHAR(1023),
			sasl_mechanism VARCHAR(255),
			sasl_plain_username VARCHAR(255),
			sasl_plain_password VARCHAR(255),
			sasl_external_cert BLOB DEFAULT NULL,
			sasl_external_key BLOB DEFAULT NULL,
			FOREIGN KEY(user) REFERENCES User(id),
			UNIQUE(user, addr, nick),
			UNIQUE(user, name)
		);
		INSERT INTO NetworkNew
			SELECT Network.id, name, User.id as user, addr, nick,
				Network.username, realname, pass, connect_commands,
				sasl_mechanism, sasl_plain_username, sasl_plain_password,
				sasl_external_cert, sasl_external_key
			FROM Network
			JOIN User ON Network.user = User.username;
		DROP TABLE Network;
		ALTER TABLE NetworkNew RENAME TO Network;
	`,
	`
		ALTER TABLE Channel ADD COLUMN relay_detached INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE Channel ADD COLUMN reattach_on INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE Channel ADD COLUMN detach_after INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE Channel ADD COLUMN detach_on INTEGER NOT NULL DEFAULT 0;
	`,
	`
		CREATE TABLE DeliveryReceipt (
			id INTEGER PRIMARY KEY,
			network INTEGER NOT NULL,
			target VARCHAR(255) NOT NULL,
			client VARCHAR(255),
			internal_msgid VARCHAR(255) NOT NULL,
			FOREIGN KEY(network) REFERENCES Network(id),
			UNIQUE(network, target, client)
		);
	`,
	"ALTER TABLE Channel ADD COLUMN detached_internal_msgid VARCHAR(255)",
	"ALTER TABLE Network ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
	"ALTER TABLE User ADD COLUMN realname VARCHAR(255)",
	`
		CREATE TABLE NetworkNew (
			id INTEGER PRIMARY KEY,
			name TEXT,
			user INTEGER NOT NULL,
			addr TEXT NOT NULL,
			nick TEXT,
			username TEXT,
			realname TEXT,
			pass TEXT,
			connect_commands TEXT,
			sasl_mechanism TEXT,
			sasl_plain_username TEXT,
			sasl_plain_password TEXT,
			sasl_external_cert BLOB,
			sasl_external_key BLOB,
			enabled INTEGER NOT NULL DEFAULT 1,
			FOREIGN KEY(user) REFERENCES User(id),
			UNIQUE(user, addr, nick),
			UNIQUE(user, name)
		);
		INSERT INTO NetworkNew
			SELECT id, name, user, addr, nick, username, realname, pass,
				connect_commands, sasl_mechanism, sasl_plain_username,
				sasl_plain_password, sasl_external_cert, sasl_external_key,
				enabled
			FROM Network;
		DROP TABLE Network;
		ALTER TABLE NetworkNew RENAME TO Network;
	`,
	`
		CREATE TABLE ReadReceipt (
			id INTEGER PRIMARY KEY,
			network INTEGER NOT NULL,
			target TEXT NOT NULL,
			timestamp TEXT NOT NULL,
			FOREIGN KEY(network) REFERENCES Network(id),
			UNIQUE(network, target)
		);
	`,
	`
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
			network INTEGER,
			endpoint TEXT NOT NULL,
			key_vapid TEXT,
			key_auth TEXT,
			key_p256dh TEXT,
			FOREIGN KEY(network) REFERENCES Network(id),
			UNIQUE(network, endpoint)
		);
	`,
	`
		ALTER TABLE WebPushSubscription ADD COLUMN user INTEGER REFERENCES User(id);
		UPDATE WebPushSubscription AS wps SET user = (SELECT n.user FROM Network AS n WHERE n.id = wps.network);
	`,
	"ALTER TABLE User ADD COLUMN nick TEXT;",
	"ALTER TABLE Network ADD COLUMN auto_away INTEGER NOT NULL DEFAULT 1;",
	"ALTER TABLE Network ADD COLUMN certfp TEXT;",
	// SQLite doesn't support non-constant default values, so use an empty
	// string as default and update all columns in a separate statement
	`
		ALTER TABLE User ADD COLUMN created_at TEXT NOT NULL DEFAULT '';
		UPDATE User SET created_at = strftime('` + sqliteTimeFormat + `', 'now');
	`,
	"ALTER TABLE User ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1",
	"ALTER TABLE User ADD COLUMN downstream_interacted_at TEXT;",
	`
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

		CREATE TABLE MessageTarget (
			id INTEGER PRIMARY KEY,
			network INTEGER NOT NULL,
			target TEXT NOT NULL,
			FOREIGN KEY(network) REFERENCES Network(id),
			UNIQUE(network, target)
		);

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
	`,
	"ALTER TABLE User ADD COLUMN max_networks INTEGER NOT NULL DEFAULT -1",
	`
		ALTER TABLE MessageTarget ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE MessageTarget ADD COLUMN muted INTEGER NOT NULL DEFAULT 0;
	`,
	`
		CREATE INDEX Network_user_index ON Network(user);
		CREATE INDEX Channel_network_index ON Channel(network);
		CREATE INDEX DeliveryReceipt_network_index ON DeliveryReceipt(network);
		CREATE INDEX ReadReceipt_network_index ON ReadReceipt(network);
		CREATE INDEX WebPushSubscription_user_index ON WebPushSubscription(user);
		CREATE INDEX WebPushSubscription_network_index ON WebPushSubscription(network);
		CREATE INDEX Message_target_index ON Message(target);
		CREATE INDEX MessageTarget_network_index ON MessageTarget(network);
	`,
	`ALTER TABLE MessageTarget ADD COLUMN blocked INTEGER NOT NULL DEFAULT 0`,
	`
		CREATE TABLE DeviceCertificate (
			id INTEGER PRIMARY KEY,
			user INTEGER NOT NULL,
			label TEXT NOT NULL,
			fingerprint BLOB NOT NULL UNIQUE,
			last_used TEXT NOT NULL,
			FOREIGN KEY(user) REFERENCES User(id)
		);
	`,
	`ALTER TABLE DeviceCertificate ADD COLUMN last_ip TEXT NOT NULL DEFAULT ''`,
}
