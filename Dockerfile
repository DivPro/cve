FROM golang:1.15.7 AS build
MAINTAINER Alexey Shatunov <shatunov2008@gmail.com>
WORKDIR /src
COPY ./go.mod ./go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/cve main/cve/main.go

FROM scratch AS final
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /bin/cve /
ENV DB_CONN "postgres://pg-user:pg-pass@postgres:5432/pg-db"
EXPOSE 80
CMD ["/cve"]