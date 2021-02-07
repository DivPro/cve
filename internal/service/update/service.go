package update

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/divpro/cve/internal/entity/cve"

	"github.com/divpro/cve/internal/entity/lock"
	"github.com/divpro/cve/internal/service/update/source"
	"github.com/rs/zerolog/log"
)

type Service interface {
	PostUpdate(w http.ResponseWriter, r *http.Request)
}

type service struct {
	db      cve.Repository
	srvLock lock.Service
	sources []source.Source
}

func New(
	db cve.Repository,
	srvLock lock.Service,
) Service {
	return &service{
		db:      db,
		srvLock: srvLock,
		sources: []source.Source{
			source.NewDebian(),
			//source.NewRedhat(),
		},
	}
}

func (s *service) PostUpdate(w http.ResponseWriter, r *http.Request) {
	const lockID = int64(1)
	l, err := s.srvLock.Acquire(r.Context(), lockID, func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		s.processUpdate(ctx)
	})
	if err != nil {
		if errors.Is(err, lock.ErrLockExists) {
			w.WriteHeader(http.StatusLocked)
			_, _ = w.Write([]byte("update operation in progress"))
			log.Warn().Err(err).Msg("lock acquire")

			return
		}

		log.Error().Err(err).Msg("lock acquire")

		w.WriteHeader(http.StatusInternalServerError)

		return
	}
	_, err = w.Write([]byte(fmt.Sprintf(
		"lock acquired [ #%d ] at %s", l.GetID(), l.GetAcquiredAt().Format(time.RFC3339))),
	)
	if err != nil {
		log.Error().Err(err).Msg("write response")
	}
}

func (s *service) processUpdate(ctx context.Context) {
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

	err := s.db.Replace(ctx, models)
	if err != nil {
		log.Error().Err(err).Msg("truncate old")
	}

	log.Info().Int("count", len(models)).Msg("cve created")
}
