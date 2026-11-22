# The one machine both networks can reach. Failures are made here, so they're on the real path.
FROM alpine:3
RUN apk add --no-cache iproute2 iptables
