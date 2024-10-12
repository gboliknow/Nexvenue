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
	r.POST("/users/handleChangePassword", AuthMiddleware(), s.handleChangePassword)
	r.POST("/users/request-reset-password", s.handleRequestResetPassword)
	r.POST("/users/reset-password", s.handleResetPassword)
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

	otp, err := s.generateAndStoreOTP(payload.Email)
	if err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error generating OTP")
		return
	}

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
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
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

func (s *UserService) handleChangePassword(c *gin.Context) {
	userID, exists := c.Get("userID")
	var payload struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		OTP             string `json:"otp"`
	}

	if !exists {
		utility.RespondWithError(c, http.StatusBadRequest, "permission denied")
		return
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		utility.RespondWithError(c, http.StatusBadRequest, "Invalid request payload")
		return
	}
	user, err := s.store.FindUserByID(userID.(string))
	if err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error fetching user")
		return
	}
	if err := s.validateOTP(user.Email, payload.OTP); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}

	if !CheckPasswordHash(payload.CurrentPassword, user.Password) {
		utility.RespondWithError(c, http.StatusUnauthorized, "Current password is incorrect")
		return
	}
	if err := validatePassword(payload.NewPassword); err != nil {
		utility.RespondWithError(c, http.StatusBadRequest, err.Error())
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}
	hashedNewPassword, err := HashPassword(payload.NewPassword)
	if err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error hashing new password")
		return
	}

	user.Password = hashedNewPassword
	if err := s.store.UpdateUser(user); err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error updating password")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
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

func (s *UserService) generateAndStoreOTP(email string) (string, error) {
	otp := generateOTP()
	expiration := time.Now().Add(10 * time.Minute)
	s.otpStore[email] = OTPData{OTP: otp, ExpiresAt: expiration}

	return otp, nil
}

func (s *UserService) handleRequestResetPassword(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
	}

	if err := c.ShouldBindJSON(&payload); err != nil {
		utility.RespondWithError(c, http.StatusBadRequest, "Invalid request payload")
		return
	}

	var user models.User
	err := s.store.FindUserByEmail(payload.Email, &user)
	if err != nil {
		utility.RespondWithError(c, http.StatusNotFound, "User not found")
		return
	}

	otp, err := s.generateAndStoreOTP(payload.Email)
	if err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error generating OTP")
		return
	}

	if err := sendOTPEmail(user.Email, otp); err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Failed to send OTP")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to email"})
}

func (s *UserService) handleResetPassword(c *gin.Context) {
	var payload struct {
		Email       string `json:"email"`
		OTP         string `json:"otp"`
		NewPassword string `json:"new_password"`
	}

	// Validate request
	if err := c.ShouldBindJSON(&payload); err != nil {
		utility.RespondWithError(c, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := s.validateOTP(payload.Email, payload.OTP); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}

	hashedPassword, err := HashPassword(payload.NewPassword)
	if err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error hashing new password")
		return
	}

	var user models.User
	err = s.store.FindUserByEmail(payload.Email, &user)
	if err != nil {
		utility.RespondWithError(c, http.StatusNotFound, "User not found")
		return
	}

	user.Password = hashedPassword
	if err := s.store.UpdateUser(&user); err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error updating password")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully"})
}
