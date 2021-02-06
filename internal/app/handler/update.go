package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/divpro/cve/internal/service/update"

	"github.com/divpro/cve/internal/entity/lock"

	"github.com/rs/zerolog/log"
)

func PostUpdate(updateSVC update.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const lockID = int64(1)
		l, err := updateSVC.Acquire(r.Context(), lockID, func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
			defer cancel()
			updateSVC.Update(ctx)
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
}
