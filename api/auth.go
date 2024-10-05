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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/exp/rand"
)

var (
	errEmailRequired       = errors.New("email is required")
	errInvalidEmail        = errors.New("invalid email format")
	// errFirstNameRequired   = errors.New("first name is required")
	// errLastNameRequired    = errors.New("last name is required")
	// errPasswordRequired    = errors.New("password is required")
	// errPasswordStrength    = errors.New("password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character")
	// errTitleRequired       = errors.New("title is required")
	// errDescriptionRequired = errors.New("description is required")
	// errGenreRequired       = errors.New("genre is required")
	// errReleaseDateRequired = errors.New("release date is required and must be in the format YYYY-MM-DD")
	// errMovieIDRequired     = errors.New("movie ID is required")
	// errStartTimeRequired   = errors.New("start time is required and must be in the format YYYY-MM-DDTHH:MM:SSZ")
	// errEndTimeRequired     = errors.New("end time is required and must be in the format YYYY-MM-DDTHH:MM:SSZ")
)

func validateUserPayload(user *models.User) error {
	if user.Email == "" {
		return errEmailRequired
	}
	if validateEmail(user.Email) {
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

// func validatePassword(password string) error {
// 	if len(password) == 0 {
// 		return errPasswordRequired
// 	}

// 	if len(password) < 8 {
// 		return fmt.Errorf("password must be at least 8 characters long")
// 	}

// 	var hasUpper bool
// 	var hasLower bool
// 	var hasNumber bool
// 	var hasSpecial bool

// 	for _, char := range password {
// 		switch {
// 		case unicode.IsUpper(char):
// 			hasUpper = true
// 		case unicode.IsLower(char):
// 			hasLower = true
// 		case unicode.IsNumber(char):
// 			hasNumber = true
// 		case unicode.IsPunct(char) || unicode.IsSymbol(char):
// 			hasSpecial = true
// 		}
// 	}

// 	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
// 		return errPasswordStrength
// 	}

// 	return nil
// }

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

func SendEmail(to, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	username := os.Getenv("SMTP_USERNAME")
	password := os.Getenv("SMTP_PASSWORD")

	auth := smtp.PlainAuth("", username, password, host)
	// Email message headers and body
	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", username, to, subject, body)
	// Send email
	addr := fmt.Sprintf("%s:%s", host, port)
	if err := smtp.SendMail(addr, auth, username, []string{to}, []byte(msg)); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}

func generateOTP() string {
	rand.Seed(uint64(time.Now().UnixNano()))
	otp := fmt.Sprintf("%06d", rand.Intn(1000000)) // Generates a 6-digit OTP
	return otp
}

func sendOTPEmail(email, otp string) error {
	subject := "Your OTP Code"
	body := fmt.Sprintf("Your OTP code is: %s", otp)
	if err := SendEmail(email, subject, body); err != nil {
		return fmt.Errorf("failed to send OTP email: %w", err)
	}
	fmt.Printf("Sending OTP %s to email %s\n", otp, email)
	return fmt.Errorf("OTP sent successfully")
}

func sendPasswordEmail(email, password string) error {
	subject := "Your Password"
	body := fmt.Sprintf("Your Password Is : %s , Please change it ASAP", password)
	if err := SendEmail(email, subject, body); err != nil {
		return fmt.Errorf("failed to send OTP email: %w", err)
	}
	fmt.Printf("Sending password %s to email %s\n", password, email)
	return fmt.Errorf("password sent successfully")
}


func GenerateRandomPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

