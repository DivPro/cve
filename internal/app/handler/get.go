package handler

import (
	"encoding/json"
	"net/http"

	"github.com/divpro/cve/internal/service/get"

	"github.com/divpro/cve/internal/entity/cve"
	"github.com/go-chi/chi"
	"github.com/rs/zerolog/log"
)

func GetById(getSVC get.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		source := q.Get("source")
		pkg := q.Get("pkg")
		id := chi.URLParam(r, "id")

		models, err := getSVC.GetByID(r.Context(), &cve.FindFilter{
			ID:      id,
			Package: pkg,
			Source:  source,
		})
		if err != nil {
			log.Error().Err(err).Msg("db find cve")

			w.WriteHeader(http.StatusInternalServerError)

			return
		}
		panic("lolg")
		enc := json.NewEncoder(w)
		enc.SetIndent("\t", "")
		err = enc.Encode(models)
		if err != nil {
			log.Error().Err(err).Msg("encode cve response")
		}
	}
}
