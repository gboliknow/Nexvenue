package api

import (
	"errors"
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
	r.POST("/users/sendOtp", s.handleSendOTP)
	r.POST("/users/verify", s.handleVerifyOTP)
	r.POST("/users/register", s.handleRegister)
	r.POST("/users/login", s.handleUserLogin)
}

func (s *UserService) handleSendOTP(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
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

func (s *UserService) handleVerifyOTP(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}

	if err := s.validateOTP(payload.Email, payload.OTP); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP verified"})
}

func (s *UserService) handleRegister(c *gin.Context) {
	var registerRequest models.RegisterRequest
	if err := c.ShouldBindJSON(&registerRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}
	if err := validateUserPayload(&registerRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := s.validateOTP(registerRequest.Email, registerRequest.OTP); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}
	password, err := GenerateRandomPassword()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error generating password"})
		return
	}
	newUser := models.User{
		Email:     registerRequest.Email,
		Role:      registerRequest.Role,
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

	if err := sendPasswordEmail(registerRequest.Email, password); err != nil {
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

func (s *UserService) handleUserLogin(c *gin.Context) {
	var loginRequest models.LoginRequest
	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Find the user by email
	var user models.User
	if err := s.store.FindUserByEmail(loginRequest.EmailOrUserTag, &user); err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "User not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal server error"})
		}
		return
	}

	if !CheckPasswordHash(loginRequest.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid email or password"})
		return
	}
	// Generate JWT token
	token, err := createAndSetAuthCookie(user.ID, c.Writer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token"})
		return
	}

	responseData := models.UserResponse{
		ID:             user.ID,
		FirstName:      user.FirstName,
		LastName:       user.LastName,
		Email:          user.Email,
		CreatedAt:      user.CreatedAt,
		Address:        user.Address,
		Phone:          user.Phone,
		Role:           user.Role,
		ProfilePicture: user.ProfilePicture,
		IsVerified:     user.IsVerified,
		Bio:            user.Bio,
		UserTag:        user.UserTag,
	}

	utility.WriteJSON(c.Writer, http.StatusOK, "User created successfully", gin.H{
		"user":  responseData,
		"token": token,
	})
}

func (s *UserService) validateOTP(email, otp string) error {
	storedData, exists := s.otpStore[email]
	if !exists || storedData.OTP != otp {
		return errors.New("invalid OTP")
	}
	if time.Now().After(storedData.ExpiresAt) {
		delete(s.otpStore, email)
		return errors.New("OTP has expired")
	}
	return nil
}
