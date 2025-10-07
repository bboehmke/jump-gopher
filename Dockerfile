FROM golang:1.25 AS builder

COPY . /src/
WORKDIR /src/

RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /jump-gopher .

FROM scratch

# copy app from build image
COPY --from=builder /jump-gopher /jump-gopher
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
EXPOSE 2222
VOLUME ["/data"]
WORKDIR "/"

ENTRYPOINT ["/jump-gopher"]
