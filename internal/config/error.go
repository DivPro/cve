package config

import "fmt"

type configurationErrors []error

func (e configurationErrors) Error() string {
	err := "configuration errors:\n"
	for _, e := range e {
		err += fmt.Sprintf("\tfield %s\n", e.Error())
	}

	return err
}

