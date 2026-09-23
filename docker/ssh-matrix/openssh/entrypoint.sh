#!/bin/sh
set -eu

KEYDIR="${RUSTMITE_KEYDIR:-/keys}"

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
  if [ -f "$KEYDIR/host_ed25519" ]; then
    cp "$KEYDIR/host_ed25519" /etc/ssh/ssh_host_ed25519_key
    cp "$KEYDIR/host_ed25519.pub" /etc/ssh/ssh_host_ed25519_key.pub
  else
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N '' -q
  fi
fi
chmod 600 /etc/ssh/ssh_host_ed25519_key
chmod 644 /etc/ssh/ssh_host_ed25519_key.pub || true

if [ -f "$KEYDIR/authorized_keys" ]; then
  mkdir -p /home/rustmite/.ssh
  cp "$KEYDIR/authorized_keys" /home/rustmite/.ssh/authorized_keys
fi
chmod 700 /home/rustmite/.ssh
chmod 600 /home/rustmite/.ssh/authorized_keys
chown -R rustmite:rustmite /home/rustmite/.ssh

mkdir -p /var/run/sshd

# Docker Desktop mounts /dev/shm noexec; provide an exec-capable staging area
# for Method B / stage-0 bootstrap (docs/04 §3).
mkdir -p /run/rustmite-exec
mount -t tmpfs -o exec,nosuid,nodev,mode=1777 tmpfs /run/rustmite-exec
chmod 1777 /run/rustmite-exec

if [ "${RUSTMITE_NOEXEC_TMP:-0}" = "1" ]; then
  mount -t tmpfs -o noexec,nosuid,nodev,mode=1777 tmpfs /tmp
fi

exec /usr/sbin/sshd -D -e
