package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/divpro/cve/internal/entity"

	"github.com/rs/zerolog/log"
)

type redhat struct {
	client *http.Client
	url    string
}

func NewRedhat() Source {
	return &redhat{
		client: &http.Client{
			Timeout: time.Minute * 10,
		},
		url: "https://access.redhat.com/labs/securitydataapi/cve.json?page=%d&per_page=%d&after=%s",
	}
}

func (s redhat) Download(ctx context.Context) ([]entity.CVE, error) {
	// process list pages

	// name => url
	urlMap := make(map[string]string)
	const perPage = 5000
	pageNum := 0
	for {
		pageNum++
		url := fmt.Sprintf(s.url, pageNum, perPage, "")

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}

		resp, err := s.client.Do(req)
		if err != nil {
			return nil, err
		}

		var items []struct {
			CVE string `json:"CVE"`
			URL string `json:"resource_url"`
		}
		dec := json.NewDecoder(resp.Body)
		err = dec.Decode(&items)
		if err != nil {
			return nil, err
		}

		if len(items) == 0 {
			break
		}

		for _, item := range items {
			urlMap[item.CVE] = item.URL
		}

		log.Debug().Str("url", url).Int("cnt", len(items)).Msg("list completed")
	}

	log.Debug().Int("total", len(urlMap)).Msg("total urls collected")

	// process separate CVE pages
	urls := make(chan string, len(urlMap))
	for _, url := range urlMap {
		urls <- url
	}
	close(urls)
	errs := make(chan error, len(urlMap))
	cve := make(chan entity.CVE)
	var result []entity.CVE

	const workerCount = 100
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for url := range urls {
				log.Debug().Str("url", url).Msg("processing cve url")

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if err != nil {
					errs <- err

					continue
				}

				resp, err := s.client.Do(req)
				if err != nil {
					errs <- err

					continue
				}
				b, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					errs <- err

					_ = resp.Body.Close()
					continue
				}
				_ = resp.Body.Close()

				var item struct {
					Name     string `json:"name"`
					Packages []struct {
						Package string `json:"package"`
					} `json:"affected_release"`
				}
				err = json.Unmarshal(b, &item)
				if err != nil {
					errs <- err

					continue
				}

				for _, p := range item.Packages {
					cve <- entity.CVE{
						ID:          item.Name,
						PackageName: p.Package,
						Body:        string(b),
						Source:      sourceRedhat,
					}
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case err := <-errs:
				log.Error().Err(err).Msg("cve page")
			case item := <-cve:
				result = append(result, item)
			default:
				break
			}
		}
	}()
	wg.Wait()

	return result, nil
}

func (s redhat) GetName() string {
	return sourceRedhat
}
