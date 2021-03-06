-- Add up migration script here

CREATE TABLE IF NOT EXISTS Accounts (
    id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
    -- encrypted with salt
    encrypted_privkey BINARY(32) NOT NULL,
    salt BINARY(16) NOT NULL,

    -- long name since `description` is a reserved keyword
    account_description TEXT
);

-- Those funny stuff is to constrain this table to only one row.
-- Not a sql expert here, feel free to change it if you know more.
CREATE TABLE IF NOT EXISTS MasterPassword (
    master_password_uniqueness CHAR(32) NOT NULL DEFAULT "Only one master password allowed",

    -- hash with salt
    password_hash BINARY(32) NOT NULL,
    salt BINARY(16) NOT NULL,

    CONSTRAINT pk_master_password PRIMARY KEY (master_password_uniqueness),
    CONSTRAINT ck_master_password_uniqueness CHECK (master_password_uniqueness = "Only one master password allowed")
);
