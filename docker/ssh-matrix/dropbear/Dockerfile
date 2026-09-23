FROM alpine:3.20
RUN apk add --no-cache dropbear dropbear-dbclient \
    && adduser -D -s /bin/sh rustmite \
    && passwd -u rustmite \
    && mkdir -p /home/rustmite/.ssh /etc/dropbear \
    && chmod 700 /home/rustmite/.ssh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
