#!/bin/sh
set -eu
KEYDIR="${RUSTMITE_KEYDIR:-/keys}"
if [ ! -f /etc/dropbear/dropbear_ed25519_host_key ]; then
  dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key >/dev/null
fi
if [ -f "$KEYDIR/authorized_keys" ]; then
  mkdir -p /home/rustmite/.ssh
  # Convert OpenSSH pubkey to dropbear-authorized form (same authorized_keys format works)
  cp "$KEYDIR/authorized_keys" /home/rustmite/.ssh/authorized_keys
  chmod 700 /home/rustmite/.ssh
  chmod 600 /home/rustmite/.ssh/authorized_keys
  chown -R rustmite:rustmite /home/rustmite/.ssh
fi
mkdir -p /run/rustmite-exec
mount -t tmpfs -o exec,nosuid,nodev,mode=1777 tmpfs /run/rustmite-exec || true
exec dropbear -F -E -p 22 -w -s
