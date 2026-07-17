#!/bin/sh
# Runs after the package installs nftably. Creates the service account and its
# state directory, then reloads systemd. It does NOT start nftably: the operator
# runs "nftably init" first to create the admin account.
set -e

# Create a system user/group for the service if they don't exist.
if ! getent group nftably >/dev/null 2>&1; then
	groupadd --system nftably
fi
if ! getent passwd nftably >/dev/null 2>&1; then
	useradd --system --gid nftably --home-dir /var/lib/nftably \
		--shell /usr/sbin/nologin --comment "nftably service account" nftably
fi

# State directory, owned by the service account.
mkdir -p /var/lib/nftably
chown -R nftably:nftably /var/lib/nftably
chmod 0750 /var/lib/nftably

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload || true
fi

cat <<'EOF'

nftably installed.

Next steps:
  1. sudo nftably init          # create the admin account
  2. sudo nftably doctor        # check nft access and the database
  3. sudo systemctl enable --now nftably

By default nftably listens on 0.0.0.0:8080 with no TLS. Set the access list
under Settings -> Access control as soon as you log in, or bind it to loopback
(edit the unit's --listen to 127.0.0.1:8080) and reach it over an SSH tunnel.
EOF

exit 0
