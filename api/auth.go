package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/smtp"
	"nexvenue/internal/config"
	"nexvenue/internal/models"
	"nexvenue/internal/utility"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"

	"crypto/rand"
	"math/big"

	ratelimit "github.com/JGLTechnologies/gin-rate-limit"
)

var (
	errEmailRequired = errors.New("email is required")
	errInvalidEmail  = errors.New("invalid email format")
	// errFirstNameRequired   = errors.New("first name is required")
	// errLastNameRequired    = errors.New("last name is required")
	errPasswordRequired = errors.New("password is required")
	errPasswordStrength = errors.New("password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character")
	// errTitleRequired       = errors.New("title is required")
	// errDescriptionRequired = errors.New("description is required")
	// errGenreRequired       = errors.New("genre is required")
	// errReleaseDateRequired = errors.New("release date is required and must be in the format YYYY-MM-DD")
	// errMovieIDRequired     = errors.New("movie ID is required")
	// errStartTimeRequired   = errors.New("start time is required and must be in the format YYYY-MM-DDTHH:MM:SSZ")
	// errEndTimeRequired     = errors.New("end time is required and must be in the format YYYY-MM-DDTHH:MM:SSZ")
)

func validateUserPayload(user *models.RegisterRequest) error {
	if user.Email == "" {
		return errEmailRequired
	}
	if !validateEmail(user.Email) {
		return errInvalidEmail
	}

	validRoles := map[string]bool{
		"user":      true,
		"admin":     true,
		"organizer": true,
	}

	if _, ok := validRoles[user.Role]; !ok {
		return fmt.Errorf("invalid role: %s", user.Role)
	}
	return nil
}

func validateEmail(email string) bool {
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(email)
}

func validatePassword(password string) error {
	if len(password) == 0 {
		return errPasswordRequired
	}

	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	var hasUpper bool
	var hasLower bool
	var hasNumber bool
	var hasSpecial bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errPasswordStrength
	}

	return nil
}

func CreateJWT(secret []byte, userID string) (string, error) {
	// Create a new JWT token with userID and expiration claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID":    userID,
		"expiresAt": time.Now().Add(time.Hour * 24 * 1).Unix(),
	})

	// Sign the token with the provided secret
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func validateJWT(tokenString string) (*jwt.Token, error) {
	secret := os.Getenv("JWT_SECRET")
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := utility.GetTokenFromRequest(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid token"})
			c.Abort()
			return
		}

		token, err := validateJWT(tokenString)
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "permission denied"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			c.Abort()
			return
		}

		userID, ok := claims["userID"].(string)
		if !ok || userID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "userID not found in token"})
			c.Abort()
			return
		}
		c.Set("userID", userID)
		c.Next()
	}
}

func RequireAdminMiddleware(store Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		requesterID, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "permission denied"})
			c.Abort()
			return
		}
		requester, err := store.FindUserByID(requesterID.(string))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			c.Abort()
			return
		}

		if requester.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied: Only admins are authorized to perform this action."})
			c.Abort()
			return
		}

		c.Next()
	}
}

func createAndSetAuthCookie(userID string, w http.ResponseWriter) (string, error) {
	secret := []byte(config.Envs.JWTSecret)
	token, err := CreateJWT(secret, userID)
	if err != nil {
		return "", err
	}

	http.SetCookie(w, &http.Cookie{
		Name:  "Authorization",
		Value: token,
	})

	return token, nil
}

// func SendEmail(to, subject, body string) error {
// 	host := os.Getenv("SMTP_HOST")
// 	port := os.Getenv("SMTP_PORT")
// 	username := os.Getenv("SMTP_USERNAME")
// 	password := os.Getenv("SMTP_PASSWORD")

// 	// Email message headers and body
// 	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", username, to, subject, body)
// 	auth := smtp.PlainAuth("", username, password, host)
// 	// Send email
// 	addr := fmt.Sprintf("%s:%s", host, port)
// 	if err := smtp.SendMail(addr, auth, username, []string{to}, []byte(msg)); err != nil {
// 		log.Info().Str("addr", addr).Err(err).Msg("Failed to send email")
// 		return fmt.Errorf("failed to send email: %w", err)
// 	}
// 	return nil
// }

func SendEmailWithRetry(to, subject, body string, maxRetries int) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")

	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", username, to, subject, body)
	auth := smtp.PlainAuth("", username, password, host)
	addr := fmt.Sprintf("%s:%s", host, port)

	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err = smtp.SendMail(addr, auth, username, []string{to}, []byte(msg))
		if err == nil {
			return nil
		}

		// Log each failed attempt
		log.Info().Str("addr", addr).Err(err).Msgf("Failed to send email, retrying... attempt %d", attempt+1)

		// Wait for a second before retrying
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("failed to send email after %d attempts: %w", maxRetries, err)
}

// func generateOTP() string {
// 	otpLength := 6
// 	otp := make([]byte, otpLength)
// 	for i := 0; i < otpLength; i++ {
// 		num, _ := rand.Int(rand.Reader, big.NewInt(10))
// 		otp[i] = byte(num.Int64() + '0') // Convert number to a character '0'-'9'
// 	}
// 	return string(otp)
// }

func generateOTP() (string, error) {
	otp := make([]byte, 6)
	for i := 0; i < 6; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		otp[i] = byte(num.Int64() + '0')
	}
	return string(otp), nil
}

func sendOTPEmail(email, otp string) (string, error) {
	subject := "Your OTP Code"
	expirationTime := "10 minutes" // example
	body := fmt.Sprintf("Hello from Nexvenue!\n\nYour One-Time Password (OTP) is: %s.\nThis code is valid for %s.\nPlease use it to complete your verification process. If you did not request this, kindly ignore this message.\n\nThank you for using Nexvenue!", otp, expirationTime)
	if err := SendEmailWithRetry(email, subject, body, 3); err != nil {
		return "", fmt.Errorf("failed to send OTP email: %w", err)
	}
	fmt.Printf("Sending OTP %s to email %s\n", otp, email)
	return "OTP sent successfully", nil
}

func sendPasswordEmail(email, password string) (string, error) {
	subject := "Your Nexvenue Account Password"
	body := fmt.Sprintf("Hi,\n\nYour password is: %s.\nPlease change your password immediately to ensure the security of your account.\n\nIf you didn't request this, please contact support.\n\nBest regards,\nThe Nexvenue Team", password)
	if err := SendEmailWithRetry(email, subject, body, 3); err != nil {
		return "", fmt.Errorf("failed to send OTP email: %w", err)
	}
	fmt.Printf("Sending password %s to email %s\n", password, email)
	return "password sent successfully", nil
}

func GenerateRandomPassword() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *UserService) RateLimitMiddleware(rate time.Duration, limit uint) gin.HandlerFunc {
	store := ratelimit.RedisStore(&ratelimit.RedisOptions{
		RedisClient: s.cache.Client,
		Rate:        rate,
		Limit:       limit,
	})

	return ratelimit.RateLimiter(store, &ratelimit.Options{
		ErrorHandler: errorHandler,
		KeyFunc:      keyFunc,
	})
}

func keyFunc(c *gin.Context) string {
	return c.ClientIP()
}

func errorHandler(c *gin.Context, info ratelimit.Info) {
	c.String(http.StatusTooManyRequests, "Too many requests. Try again in %s", time.Until(info.ResetTime).String())
}

func StripEmailDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return email
}

func RandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "" // Handle error appropriately in production
		}
		b[i] = charset[num.Int64()]
	}
	return string(b)
}


