package source

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/divpro/cve/internal/entity"

	"github.com/rs/zerolog/log"
)

type debian struct {
	client *http.Client
	url    string
}

func NewDebian() Source {
	return &debian{
		client: &http.Client{
			Timeout: time.Minute * 10,
		},
		url: "https://security-tracker.debian.org/tracker/data/json",
	}
}

func (s debian) Download(ctx context.Context) ([]entity.CVE, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	log.Debug().Interface("headers", resp.Header).Msg("download done")

	packages := map[string]map[string]json.RawMessage{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&packages)
	if err != nil {
		return nil, err
	}

	var result []entity.CVE
	for packageName, items := range packages {
		for id, cve := range items {
			result = append(result, entity.CVE{
				PackageName: packageName,
				ID:          id,
				Body:        string(cve),
				Source:      sourceDebian,
			})
		}
	}

	return result, nil
}

func (s debian) GetName() string {
	return sourceDebian
}
