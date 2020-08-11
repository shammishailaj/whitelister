FROM golang:alpine AS builder

ARG CGO_ENABLED
ARG GOOS
ARG GOARCH

RUN apk --no-cache add git build-base
RUN go get github.com/cloudxo/govvv

RUN mkdir /go/src/whitelister

WORKDIR /go/src/whitelister

COPY . ./

RUN go env

# Following Exports are now expected from user side via a compose file
#RUN export CGO_ENABLED=0
#RUN export GOOS=linux
#RUN export GOARCH=amd64

#RUN go build -o ./cmd/whitelister/whitelister ./cmd/whitelister/whitelister.go
RUN CGO_ENABLED=0 /go/bin/govvv build -mod vendor -a -installsuffix cgo -ldflags '-extldflags "-static"' -o ./cmd/whitelister/whitelister ./cmd/whitelister/whitelister.go

#RUN ./cmd/whitelister/whitelister -version -json

# See: https://stackoverflow.com/a/52979541/6670698
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /go/src/whitelister/config /whitelister/config/
COPY --from=builder /go/src/whitelister/views /whitelister/views/
COPY --from=builder /go/src/whitelister/cmd/whitelister/whitelister /whitelister/whitelister
WORKDIR /whitelister
ENTRYPOINT ["/whitelister/whitelister"]