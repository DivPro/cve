package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

type Config struct {
	HttpAddr string
	HttpPort string
	LogLevel string

	DBConn string
}

const (
	NameAddr        = "http_addr"
	DefaultAddr     = "0.0.0.0"
	NamePort        = "http_port"
	DefaultPort     = "80"
	NameLogLevel    = "log_level"
	DefaultLogLevel = "info"
)

var (
	ErrHttpAddr = errors.New(NameAddr)
	ErrHttpPort = errors.New(NamePort)
	ErrLogLevel = errors.New(NameLogLevel)
)

func (c Config) Valid() error {
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
