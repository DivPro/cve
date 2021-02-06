package get

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/go-chi/chi"

	"github.com/divpro/cve/internal/entity"
)

type Service interface {
	GetById(w http.ResponseWriter, r *http.Request)
}

type service struct {
	db entity.CVERepo
}

func New(db entity.CVERepo) Service {
	return &service{
		db: db,
	}
}

func (s *service) GetById(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := q.Get("source")
	pkg := q.Get("pkg")
	id := chi.URLParam(r, "id")

	cve, err := s.db.Find(r.Context(), &entity.CVEFindFilter{
		ID:      id,
		Package: pkg,
		Source:  source,
	})
	if err != nil {
		log.Error().Err(err).Msg("db find cve")

		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("\t", "")
	err = enc.Encode(cve)
	if err != nil {
		log.Error().Err(err).Msg("encode cve response")
	}
}
