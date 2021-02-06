package update

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/divpro/cve/internal/entity"

	"github.com/divpro/cve/internal/service/lock"
	"github.com/divpro/cve/internal/service/update/source"
	"github.com/rs/zerolog/log"
)

type Service interface {
	PostUpdate(w http.ResponseWriter, r *http.Request)
}

type service struct {
	db      entity.CVERepo
	srvLock lock.Service
	sources []source.Source
}

func New(
	db entity.CVERepo,
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
	l, err := s.srvLock.AcquireNoWait(r.Context(), lockID)
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

	go s.processWithLock(l)
}

func (s *service) processWithLock(l *lock.Lock) {
	s.processUpdate()

	err := s.srvLock.Release(context.Background(), l)
	if err != nil {
		log.Error().Err(err).Msg("lock release")
	}

	log.Debug().Int64("id", l.GetID()).Msg("lock released")
}

func (s *service) processUpdate() {
	var (
		cve []entity.CVE
		wg  sync.WaitGroup
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

			cve = append(cve, sourceCVE...)
		}()
	}
	wg.Wait()
	log.Info().Int("count", len(cve)).Msg("cve download completed")

	ctx := context.Background()
	err := s.db.Replace(ctx, cve)
	if err != nil {
		log.Error().Err(err).Msg("truncate old")
	}

	log.Info().Int("count", len(cve)).Msg("cve created")
}
