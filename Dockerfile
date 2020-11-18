FROM golang:1.15 AS builder
WORKDIR /go/src/tproxy
COPY . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go install -v .

FROM scratch
COPY --from=builder /go/bin/tproxy /bin/tproxy
CMD ["/bin/tproxy"]
