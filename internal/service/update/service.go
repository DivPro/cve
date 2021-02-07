package update

import (
	"context"
	"sync"
	"time"

	"github.com/divpro/cve/internal/entity/cve"
	"github.com/divpro/cve/internal/entity/lock"
	"github.com/divpro/cve/internal/service/update/source"
	"github.com/rs/zerolog/log"
)

type Service interface {
	Update(ctx context.Context)
	Acquire(ctx context.Context, id int64, worker lock.WorkerFn) (lock.Lock, error)
}

type service struct {
	cveRepo cve.Repository
	srvLock lock.Repository
	sources []source.Source
}

func New(
	db cve.Repository,
	srvLock lock.Repository,
) Service {
	return &service{
		cveRepo: db,
		srvLock: srvLock,
		sources: []source.Source{
			source.NewDebian(),
			source.NewRedhat(),
		},
	}
}

func (s *service) Update(ctx context.Context) {
	var (
		models []cve.CVE
		wg     sync.WaitGroup
	)
	wg.Add(len(s.sources))
	for _, src := range s.sources {
		src := src
		go func() {
			defer wg.Done()

			t := time.Now()
			sourceCVE, err := src.Download(context.Background())
			if err != nil {
				log.Error().Err(err).Interface("source", src).Msg("update cve")

				return
			}
			log.Info().
				Str("source", src.GetName()).
				TimeDiff("download", time.Now(), t).
				Msg("download completed")

			models = append(models, sourceCVE...)
		}()
	}
	wg.Wait()
	log.Info().Int("count", len(models)).Msg("cve download completed")

	err := s.cveRepo.Replace(ctx, models)
	if err != nil {
		log.Error().Err(err).Msg("truncate old")
	}

	log.Info().Int("count", len(models)).Msg("cve created")
}

func (s *service) Acquire(ctx context.Context, id int64, worker lock.WorkerFn) (lock.Lock, error) {
	return s.srvLock.Acquire(ctx, id, worker)
}
