package get

import (
	"encoding/json"
	"net/http"

	"github.com/divpro/cve/internal/entity/cve"
	"github.com/go-chi/chi"
	"github.com/rs/zerolog/log"
)

type Service interface {
	GetById(w http.ResponseWriter, r *http.Request)
}

type service struct {
	db cve.Repository
}

func New(db cve.Repository) Service {
	return &service{
		db: db,
	}
}

func (s *service) GetById(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	source := q.Get("source")
	pkg := q.Get("pkg")
	id := chi.URLParam(r, "id")

	models, err := s.db.Find(r.Context(), &cve.FindFilter{
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
	err = enc.Encode(models)
	if err != nil {
		log.Error().Err(err).Msg("encode cve response")
	}
}
