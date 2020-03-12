CREATE TABLE User (
	username VARCHAR(255) PRIMARY KEY,
	password VARCHAR(255) NOT NULL
);

CREATE TABLE Network (
	id INTEGER PRIMARY KEY,
	user VARCHAR(255) NOT NULL,
	addr VARCHAR(255) NOT NULL,
	nick VARCHAR(255) NOT NULL,
	username VARCHAR(255),
	realname VARCHAR(255),
	FOREIGN KEY(user) REFERENCES User(username),
	UNIQUE(user, addr, nick)
);

CREATE TABLE Channel (
	id INTEGER PRIMARY KEY,
	network INTEGER NOT NULL,
	name VARCHAR(255) NOT NULL,
	FOREIGN KEY(network) REFERENCES Network(id),
	UNIQUE(network, name)
);
