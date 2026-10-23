FROM alpine:3.21
RUN apk add --no-cache nftables iproute2 socat curl conntrack-tools
CMD ["sleep", "2147483647"]
