#!/bin/sh
# Runs before the package is removed. Stop and disable the service so it is not
# left running against files that are about to disappear.
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl stop nftably.service || true
	systemctl disable nftably.service || true
fi

exit 0
