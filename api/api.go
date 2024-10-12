package api

import (
	"net/http"
	"os"

	"nexvenue/internal/cache"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

type APIServer struct {
	addr   string
	store  Store
	logger zerolog.Logger
	cache  *cache.RedisCache
}

func NewAPIServer(addr string, store Store) *APIServer {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).With().Timestamp().Logger()
	redisCache := cache.NewRedisCache()
	return &APIServer{addr: addr, store: store, logger: logger, cache: redisCache}
}

func (s *APIServer) Serve() {
	router := gin.Default()
	apiV1 := router.Group("/api/v1")

	//registering the routes
	userService := NewUserService(s.store, s.cache)
	userService.RegisterRoutes(apiV1)

	s.logger.Info().Str("addr", s.addr).Msg("Starting API server")
	if err := http.ListenAndServe(s.addr, router); err != nil {
		s.logger.Fatal().Err(err).Msg("Server stopped")
	}
}
