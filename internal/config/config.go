package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

type Config struct {
	HttpAddr string
	HttpPort string
	LogLevel string

	DBConn string
}

const (
	nameAddr        = "http_addr"
	defaultAddr     = "0.0.0.0"
	namePort        = "http_port"
	defaultPort     = "80"
	nameLogLevel    = "log_level"
	defaultLogLevel = "info"
)

var (
	parseFlagsOnce sync.Once

	ErrHttpAddr = errors.New(nameAddr)
	ErrHttpPort = errors.New(namePort)
	ErrLogLevel = errors.New(nameLogLevel)
)

func New() (*Config, error) {
	conf := new(Config)

	parseFlagsOnce.Do(func() {
		flag.StringVar(&conf.HttpAddr, nameAddr, defaultAddr, "http addr")
		flag.StringVar(&conf.HttpPort, namePort, defaultPort, "http port")
		flag.StringVar(&conf.LogLevel, nameLogLevel, defaultLogLevel, "log level")

		flag.Parse()

		dbDSN := os.Getenv("DB_CONN")
		if dbDSN == "" {
			conf.DBConn = "postgres://pg-user:pg-pass@127.0.0.1:5432/pg-db"
		} else {
			conf.DBConn = dbDSN
		}
	})

	if err := conf.valid(); err != nil {
		return nil, err
	}

	return conf, nil
}

func (c Config) valid() error {
	var errs []error

	if c.HttpAddr == "" {
		errs = append(errs, fmt.Errorf("%w is required", ErrHttpAddr))
	}
	if c.HttpPort == "" {
		errs = append(errs, fmt.Errorf("%w is required", ErrHttpPort))
	}
	if c.LogLevel == "" {
		errs = append(errs, fmt.Errorf("%w is required", ErrLogLevel))
		errs = append(errs, fmt.Errorf("%w is required", ErrLogLevel))
	} else {
		_, err := zerolog.ParseLevel(c.LogLevel)
		if err != nil {
			const (
				minLevel = 0
				maxLevel = 5
			)
			levels := make([]string, 0, maxLevel)
			for lvl := minLevel; lvl < maxLevel; lvl++ {
				levels = append(levels, zerolog.Level(lvl).String())
			}

			errs = append(errs, fmt.Errorf(
				"%w invalid: %s. Valid is one of: %s",
				ErrLogLevel,
				c.LogLevel,
				strings.Join(levels, ", "),
			))
		}
	}

	if len(errs) == 0 {
		return nil
	}

	return configurationErrors(errs)
}
