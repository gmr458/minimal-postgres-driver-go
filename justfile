dev:
    go run .

build:
    go build -ldflags='-s -w' .

fmt:
    gofmt -w -l .
    just --fmt

run:
    go build -ldflags='-s -w' .
    ./example-driver-go
