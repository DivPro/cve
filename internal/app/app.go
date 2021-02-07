package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/divpro/cve/internal/config"
	"github.com/divpro/cve/internal/entity/cve"
	"github.com/divpro/cve/internal/entity/lock"
	"github.com/divpro/cve/internal/service/get"
	"github.com/divpro/cve/internal/service/update"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
)

type app struct {
	server *http.Server
	db     *sqlx.DB
	svc    struct {
		update update.Service
		get    get.Service
	}
}

type appInitializer func(conf *config.Config) error

func (a *app) init(conf *config.Config) error {
	initializers := []appInitializer{
		a.initDB,
		a.initServices,
		a.initHttp,
	}

	for _, initializer := range initializers {
		err := initializer(conf)

		if err != nil {
			return err
		}
	}

	return nil
}

func (a *app) initDB(conf *config.Config) error {
	db, err := sqlx.Connect("pgx", conf.DBConn)
	if err != nil {
		return err
	}

	a.db = db

	return nil
}

func (a *app) initServices(*config.Config) error {
	svcLock := lock.New(a.db)
	cveRepo := cve.NewCVERepo(a.db)

	a.svc.update = update.New(cveRepo, svcLock)
	a.svc.get = get.New(cveRepo)

	return nil
}

func (a *app) initHttp(conf *config.Config) error {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(30 * time.Second))

	addr := fmt.Sprintf("%s:%s", conf.HttpAddr, conf.HttpPort)
	r.Route("/api", func(r chi.Router) {
		r.Get("/update", a.svc.update.PostUpdate)
		r.Get("/cve/{id}", a.svc.get.GetById)
	})

	a.server = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	return nil
}

func (a *app) runHttp() {
	log.Info().Str("addr", a.server.Addr).Msg("start http")

	err := a.server.ListenAndServe()
	if err != nil {
		log.Fatal().Err(err).Msg("listen http")
	}
}

func Run(conf *config.Config) (err error) {
	app := new(app)

	err = app.init(conf)
	if err != nil {
		return
	}
	go app.runHttp()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return app.server.Shutdown(ctx)
}
