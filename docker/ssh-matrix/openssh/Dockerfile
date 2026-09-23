FROM alpine:3.20

RUN apk add --no-cache openssh-server openssh-keygen bash coreutils \
    && adduser -D -s /bin/sh rustmite \
    && passwd -u rustmite \
    && mkdir -p /home/rustmite/.ssh /var/run/sshd \
    && chmod 700 /home/rustmite/.ssh

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
