FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/siem ./cmd/siem \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/loggen ./cmd/loggen

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/siem /out/loggen /app/
COPY rules /app/rules
COPY intel /app/intel
EXPOSE 8080
VOLUME /app/data
ENTRYPOINT ["/app/siem", "-listen", "0.0.0.0:8080"]
