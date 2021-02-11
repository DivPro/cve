package source

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/divpro/cve/internal/entity/cve"
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

func (s redhat) Download(ctx context.Context) ([]cve.CVE, error) {
	urls := make(chan string)
	errs := make(chan error)
	items := make(chan cve.CVE)

	// sequential list fetch and send to reader pool
	go func() {
		const (
			perPage  = 5000
			limitTPS = time.Millisecond * 100
		)
		var (
			pageNum uint64
			total   uint64
		)

		limiter := time.NewTicker(limitTPS)
		defer limiter.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Debug().Msg("fetch canceled")
				return
			default:
			}

			pageNum++
			url := fmt.Sprintf(s.url, pageNum, perPage, "")

			<-limiter.C
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				errs <- fmt.Errorf("new request: %w", err)
				return
			}

			resp, err := s.client.Do(req)
			if err != nil {
				errs <- fmt.Errorf("new request: %w", err)
				return
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				errs <- fmt.Errorf("new request: %w", err)
				return
			}

			var items []struct {
				CVE string `json:"CVE"`
				URL string `json:"resource_url"`
			}
			dec := json.NewDecoder(resp.Body)
			err = dec.Decode(&items)
			if err != nil {
				_ = resp.Body.Close()
				errs <- fmt.Errorf("new request: %w", err)
				return
			}
			_ = resp.Body.Close()

			if len(items) == 0 {
				break
			}

			for _, item := range items {
				total++
				urls <- item.URL
			}
		}
		close(urls)
		log.Info().Uint64("total", total).Msg("total urls")
	}()

	// reader worker pool
	go func() {
		const (
			workerCount = 100
			limitTPS    = time.Millisecond * 100
			statTPS     = time.Second
		)
		var (
			wg              sync.WaitGroup
			totalURL        uint64
			totalItems      uint64
			restartStatOnce sync.Once
		)

		// log statistic
		statTicker := time.NewTicker(statTPS)
		defer statTicker.Stop()
		// and stop it immediately to start later
		statTicker.Stop()

		go func() {
			for range statTicker.C {
				log.Info().
					Uint64("urls", atomic.LoadUint64(&totalURL)).
					Uint64("items", atomic.LoadUint64(&totalItems)).
					Msg("ended")
			}
		}()

		wg.Add(workerCount)
		limiter := time.NewTicker(limitTPS)
		defer limiter.Stop()
		for i := 0; i < workerCount; i++ {
			go func(i int) {
				defer wg.Done()
				log.Debug().Int("worker", i).Msg("started")
				for url := range urls {
					select {
					case <-ctx.Done():
						log.Debug().Msg("fetch canceled")
						return
					default:
					}

					log.Debug().Str("url", url).Msg("processing cve url")

					<-limiter.C

					// start log stat with the first item fetch
					restartStatOnce.Do(func() {
						statTicker.Reset(statTPS)
					})

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
						PackageState []struct {
							Package string `json:"package_name"`
						} `json:"package_state"`
					}
					err = json.Unmarshal(b, &item)
					if err != nil {
						errs <- err

						continue
					}

					atomic.AddUint64(&totalURL, 1)
					for _, p := range item.Packages {
						items <- cve.CVE{
							ID:          item.Name,
							PackageName: p.Package,
							Body:        string(b),
							Source:      sourceRedhat,
						}
						atomic.AddUint64(&totalItems, 1)
					}
					for _, p := range item.PackageState {
						items <- cve.CVE{
							ID:          item.Name,
							PackageName: p.Package,
							Body:        string(b),
							Source:      sourceRedhat,
						}
						atomic.AddUint64(&totalItems, 1)
					}
				}
				log.Debug().Int("worker", i).Msg("ended")
			}(i)
		}

		wg.Wait()
		close(errs)
		close(items)

		log.Info().
			Uint64("url", atomic.LoadUint64(&totalURL)).
			Uint64("items", atomic.LoadUint64(&totalItems)).
			Msg("ended")
	}()

	// collect results
	var result []cve.CVE
OUTER:
	for {
		select {
		case err := <-errs:
			return nil, err
		case item, ok := <-items:
			if !ok {
				break OUTER
			}
			result = append(result, item)
		}
	}

	return result, nil
}

func (s redhat) GetName() string {
	return sourceRedhat
}
