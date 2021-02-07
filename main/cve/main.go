package main

import (
	"flag"
	"os"

	"github.com/divpro/cve/internal/app"

	"github.com/divpro/cve/internal/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	conf := new(config.Config)
	fs := flag.NewFlagSet("main", flag.ExitOnError)
	fs.StringVar(&conf.HttpAddr, config.NameAddr, config.DefaultAddr, "http addr")
	fs.StringVar(&conf.HttpPort, config.NamePort, config.DefaultPort, "http port")
	fs.StringVar(&conf.LogLevel, config.NameLogLevel, config.DefaultLogLevel, "log level")

	err := fs.Parse(os.Args[1:])
	if err != nil {
		log.Fatal().Err(err).Msg("parse config")
	}

	dbDSN := os.Getenv("DB_CONN")
	if dbDSN == "" {
		conf.DBConn = "postgres://pg-user:pg-pass@127.0.0.1:5432/pg-db"
	} else {
		conf.DBConn = dbDSN
	}

	if err = conf.Valid(); err != nil {
		log.Fatal().Err(err).Msg("validate config")
	}

	logLevel, _ := zerolog.ParseLevel(conf.LogLevel)
	zerolog.SetGlobalLevel(logLevel)
	log.Debug().Interface("config", conf).Msg("")

	err = app.Run(conf)
	if err != nil {
		log.Fatal().Err(err).Msg("start app")
	}
}
