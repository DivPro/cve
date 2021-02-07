package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/divpro/cve/internal/app/handler"
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
	repo   struct {
		cve  cve.Repository
		lock lock.Repository
	}
	svc struct {
		update update.Service
		get    get.Service
	}
}

// panic is normal
type appInitializer func(conf *config.Config)

func (a *app) init(conf *config.Config) {
	initializers := []appInitializer{
		a.initDB,
		a.initRepositories,
		a.initServices,
		a.initHttp,
	}

	for _, initializer := range initializers {
		initializer(conf)
	}
}

func (a *app) initRepositories(*config.Config) {
	a.repo.lock = lock.New(a.db)
	a.repo.cve = cve.NewCVERepo(a.db)
}

func (a *app) initDB(conf *config.Config) {
	a.db = sqlx.MustConnect("pgx", conf.DBConn)
}

func (a *app) initServices(*config.Config) {
	a.svc.update = update.New(a.repo.cve, a.repo.lock)
	a.svc.get = get.New(a.repo.cve)
}

func (a *app) initHttp(conf *config.Config) {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(middleware.Timeout(30 * time.Second))

	addr := fmt.Sprintf("%s:%s", conf.HttpAddr, conf.HttpPort)
	r.Route("/api", func(r chi.Router) {
		r.Get("/update", handler.PostUpdate(a.svc.update))
		r.Get("/cve/{id}", handler.GetById(a.svc.get))
	})

	a.server = &http.Server{
		Addr:    addr,
		Handler: r,
	}
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

	defer func() {
		if p := recover(); err != nil {
			log.Error().Interface("cause", p).Msg("panic")
		}
	}()

	app.init(conf)
	go app.runHttp()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return app.server.Shutdown(ctx)
}
