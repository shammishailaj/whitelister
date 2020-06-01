FROM golang:alpine

RUN mkdir /go/src/whitelister

WORKDIR /go/src/whitelister

COPY . ./

RUN go env

RUN go build -o ./cmd/whitelister/whitelister ./cmd/whitelister/whitelister.go

CMD ./cmd/whitelister/whitelister