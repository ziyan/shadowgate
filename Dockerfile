# syntax=docker/dockerfile:1

FROM golang:1.25 AS builder

ARG VERSION=0.1.0
ARG COMMIT=unknown

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 go build -mod=vendor \
	-ldflags "-s -w -X github.com/ziyan/shadowgate/internal/version.version=${VERSION} -X github.com/ziyan/shadowgate/internal/version.commit=${COMMIT}" \
	-o /out/shadowgate ./command/

FROM alpine:3.20

# shadowgate shells out to `ip` to configure the tun interface.
RUN apk add --no-cache iproute2

COPY --from=builder /out/shadowgate /usr/local/bin/shadowgate

ENTRYPOINT ["/usr/local/bin/shadowgate"]
