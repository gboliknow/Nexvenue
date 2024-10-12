package utility

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"nexvenue/internal/models"
	"strings"

	"github.com/gin-gonic/gin"
)

func WriteJSON(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := models.Response{
		StatusCode: statusCode,
		Message:    message,
		Data:       data,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Error encoding response", http.StatusInternalServerError)
	}
}

func  RespondWithError(c *gin.Context, statusCode int, message string) {
    c.JSON(statusCode, gin.H{"message": message})
}

func GetTokenFromRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	headerParts := strings.Split(authHeader, " ")
	errTokenMissing := errors.New("missing or invalid token")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		return "", errTokenMissing
	}
	tokenAuth := headerParts[1]
	if tokenAuth != "" {
		return tokenAuth, nil
	}
	return "", errTokenMissing
}

func GenerateResetToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}
	return fmt.Sprintf("%x", b)
}


