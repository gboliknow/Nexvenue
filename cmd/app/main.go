package main

import (
	"fmt"
	"nexvenue/api"
	"nexvenue/internal/config"
	"nexvenue/internal/database"

	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	log.Info().Msg("Starting Nexvenue project")
	dsn := os.Getenv("DB_URL")
	connStr := fmt.Sprintf(dsn,
		config.Envs.DBUser,
		config.Envs.DBPassword,
		config.Envs.DBAddress,
		config.Envs.DBName,
	)
	log.Info().Msg(connStr)
	sqlStorage, err := database.NewPostgresStorage(connStr)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to database")
	}

	db, err := sqlStorage.InitializeDatabase()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to initialize database")
	}
	store := api.NewStore(db)
	apiServer := api.NewAPIServer(":8081", store)
	log.Info().Msg("Starting API server on port 8081")
	apiServer.Serve()
}
