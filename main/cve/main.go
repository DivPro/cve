package main

import (
	"os"

	"github.com/divpro/cve/internal/app"

	"github.com/divpro/cve/internal/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	conf, err := config.New()
	if err != nil {
		log.Fatal().Err(err).Msg("parse config")
	}
	logLevel, _ := zerolog.ParseLevel(conf.LogLevel)
	zerolog.SetGlobalLevel(logLevel)
	log.Debug().Interface("config", conf).Msg("")

	err = app.Run(conf)
	if err != nil {
		log.Fatal().Err(err).Msg("start app")
	}
}
