Tresor is a system that stores valuable key value pairs, and exposes them to
trusted parties in bundles called environments.

# User model

From the user perspective Tresor stores key-value pairs which both are unicode
strings, e.g. `backup/github_ed25519 -> <an ed25519 private key>`.

Apart from key value pairs, environments are defined as a list of 
`envvar -> key` mappings. For example, an environment "backup" may consist of a
list `[(GITHUB_IDENTITY -> backup/github_ed25519)]`. When environment is
requested, a list of pairs `envvar -> value` is returned in either json format
or in shell `.env` file format.

Keys `tresor/*` are never exposed to any environment, and are used only by
Tresor itself.

# Identities, roles, mutations

There are three main kind of identities: server, admins and readers. Each is
associated with a signing key. The key is unique among all identities. Each
identity has an associated pubkey, approved_at, compromised_at, revoked_at time.
Identities are never physically deleted from the database.

Admin can define new identities, change key->value and envvar->key associations,
and perform other database modifications. All mutations append data to the
database, i.e. the full history of mutations is preserved. Admin however cannot
see the values of key-value pairs, neither can read an environment.

When an admin is added to the database, it signs a certificate, confirming the
current identity of the server. This certificate is also stored on the server,
and is used to establish a session.

During the installation a `root` admin is initialized with its identity stored
on the server. This identity is used by the server-local invocations of the CLI,
allowing the initialization of the first non local admin. The identity is
self-signed.

Server identity is created during installation, and is signed by the root user.
Server certificates are regularly rotated, each new server certificate is signed
by the previous certificate.

Readers can only read environments to which they are authorized.

# API, sessions, transport

The API calls are performed via HTTP. First a session is requested by an
identity via a signed query, an ephemeral `age` recepient is also provided to
the server. The server replies with session id, server's certificate, signed by
the requesting identity, symmetric session key, and session timeout. This reply
is encrypted with `age`. The client then decrypts the message, verifies it, and
uses the session id and the encryption key for the follow up communication.
Within the session nonce is extensively used to avoid message replays.

The CLI tool works on top of this API. Essentially, it requires the admin
identity to be stored on a hardware key (Yubikey).

# Backup

The state of the server is regularly backed up locally, including offloading DB
snapshot into human readable CSV tables.

Remote backup is performed using `rage`. For that we store a list of recepients,
similarly with approved_at, tainted_at, revoked_at timestamps. Backup agents
(also configured by admins) are responsible for publishing the encrypted
archives to the publicly accessible internet.

# Data storage

We use SQLite3 as database engine. We do not encrypt the data in the database.

We store the following objects outside of the database:
* all certificates;
* backup agents configuration.