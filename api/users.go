package api

import (
	"net/http"
	"nexvenue/internal/models"
	"nexvenue/internal/utility"
	"time"

	"github.com/gin-gonic/gin"

	"gorm.io/gorm"
)

type OTPData struct {
	OTP       string
	ExpiresAt time.Time
}

type UserService struct {
	store    Store
	otpStore map[string]OTPData
}

func NewUserService(s Store) *UserService {
	return &UserService{store: s, otpStore: make(map[string]OTPData)}
}

func (s *UserService) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/users/register", s.handleSendOTP)
	r.POST("/users/verify", s.handleVerifyOTP)
}

func (s *UserService) handleSendOTP(c *gin.Context) {
	var payload models.User

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}

	if err := validateUserPayload(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate OTP
	otp := generateOTP()
	expiration := time.Now().Add(10 * time.Minute)
	s.otpStore[payload.Email] = OTPData{OTP: otp, ExpiresAt: expiration}

	if err := sendOTPEmail(payload.Email, otp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to send OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to email"})
}

// handleVerifyOTP handles OTP verification and creates a user after successful verification.
func (s *UserService) handleVerifyOTP(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
		Role  string `json:"role"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}

	// Verify OTP
	storedData, exists := s.otpStore[payload.Email]
	if !exists || storedData.OTP != payload.OTP {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid OTP"})
		return
	}

	if time.Now().After(storedData.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "OTP has expired"})
		delete(s.otpStore, payload.Email)
		return
	}

	password, err := GenerateRandomPassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error generating password"})
		return
	}
	newUser := models.User{
		Email:     payload.Email,
		Role:      payload.Role,
		CreatedAt: time.Now(),
		Password:  password,
	}
	hashedPassword, err := HashPassword(newUser.Password)
	if err != nil {
		utility.WriteJSON(c.Writer, http.StatusInternalServerError, "Error creating user", nil)
		return
	}

	newUser.Password = hashedPassword
	u, err := s.store.CreateUser(&newUser)
	if err != nil {
		if err == gorm.ErrDuplicatedKey {
			utility.WriteJSON(c.Writer, http.StatusConflict, "Email already exists", nil)
		} else {
			utility.WriteJSON(c.Writer, http.StatusInternalServerError, "Error creating user", nil)
		}
		return
	}

	if err := sendPasswordEmail(payload.Email, password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to send password"})
		return
	}
	token, err := createAndSetAuthCookie(u.ID, c.Writer)
	if err != nil {
		utility.WriteJSON(c.Writer, http.StatusInternalServerError, "Error creating user", nil)
		return
	}

	utility.WriteJSON(c.Writer, http.StatusCreated, "User created successfully", token)
}
