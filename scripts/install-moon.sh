#!/usr/bin/env bash
# Retry the whole installer: its own toolchain/core downloads can fail too.
set -euo pipefail

ATTEMPTS="${MOON_INSTALL_ATTEMPTS:-3}"
RETRY_DELAY="${MOON_INSTALL_RETRY_DELAY:-5}"
[[ "$ATTEMPTS" =~ ^[1-9][0-9]*$ ]] || { echo 'error: MOON_INSTALL_ATTEMPTS must be positive' >&2; exit 2; }
[[ "$RETRY_DELAY" =~ ^[0-9]+$ ]] || { echo 'error: MOON_INSTALL_RETRY_DELAY must be nonnegative' >&2; exit 2; }
INSTALLER="$(mktemp)"
trap 'rm -f "$INSTALLER"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for ((attempt = 1; attempt <= ATTEMPTS; attempt++)); do
  if curl --fail --silent --show-error --location --connect-timeout 15 --max-time 120 \
    https://cli.moonbitlang.com/install/unix.sh --output "$INSTALLER" \
    && bash "$INSTALLER"; then
    exit 0
  fi
  if [ "$attempt" -lt "$ATTEMPTS" ]; then
    echo "MoonBit install attempt $attempt/$ATTEMPTS failed; retrying in ${RETRY_DELAY}s" >&2
    sleep "$RETRY_DELAY"
  fi
done

echo "error: MoonBit installation failed after $ATTEMPTS attempts" >&2
exit 1
