FROM golang:1.22.5 as builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o goauth

FROM debian:12.8-slim
WORKDIR /app

COPY --from=builder /app/goauth /app/
RUN chmod +x /app/goauth
COPY yaml-schema.json config.yaml LICENSE /app/

ENTRYPOINT [ "/app/goauth" ]
