package api

import (
	"fmt"
	"net/http"
	"nexvenue/internal/cache"
	"nexvenue/internal/logging"
	"nexvenue/internal/models"
	"nexvenue/internal/utility"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

type OTPData struct {
	OTP       string
	ExpiresAt time.Time
}

type UserService struct {
	store    Store
	otpStore map[string]OTPData
	cache    *cache.RedisCache
	logger   zerolog.Logger
}

func NewUserService(s Store, c *cache.RedisCache, logger zerolog.Logger) *UserService {
	return &UserService{store: s, otpStore: make(map[string]OTPData), cache: c, logger: logger}
}

func (s *UserService) RegisterRoutes(r *gin.RouterGroup) {
	rateLimiter := s.RateLimitMiddleware(time.Second, 5)
	r.POST("/users/sendOtp", rateLimiter, s.handleSendOTP)
	r.POST("/users/verify", s.handleVerifyOTP)
	r.POST("/users/register", s.handleRegister)
	r.POST("/users/login", s.handleUserLogin)
	r.POST("/users/change-password", AuthMiddleware(), s.handleChangePassword)
	r.POST("/users/request-reset-password", rateLimiter, s.handleRequestResetPassword)
	r.POST("/users/reset-password", s.handleResetPassword)
}

// handleSendOTP godoc
// @Summary Send OTP to user's email
// @Description This endpoint sends a one-time password (OTP) to the specified user's email for verification.
// @Tags Users
// @Accept json
// @Produce json
// @Param request body models.SendOTPRequest true "Email Address"
// @Success 200 {object} map[string]string "OTP sent to email"
// @Failure 400 {object} map[string]string "Invalid request payload"
// @Failure 500 {object} map[string]string "Failed to send OTP"
// @Router   /api/v1/users/sendOtp [post]
func (s *UserService) handleSendOTP(c *gin.Context) {
	var payload models.SendOTPRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}
	otp, err := s.generateAndStoreOTP(payload.Email)
	if err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Error generating OTP")
		return
	}

	if _, err := sendOTPEmail(payload.Email, otp); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to email"})
}

// handleVerifyOTP godoc
// @Summary Verify OTP
// @Description This endpoint verifies the OTP sent to the user's email.
// @Tags Users
// @Accept json
// @Produce json
// @Param request body models.VerifyOTPRequest true "Email and OTP"
// @Success 200 {object} map[string]string "OTP verified"
// @Failure 400 {object} map[string]string "Invalid request payload"
// @Failure 401 {object} map[string]string "OTP verification failed"
// @Router   /api/v1/users/verify [post]
func (s *UserService) handleVerifyOTP(c *gin.Context) {
	var payload models.VerifyOTPRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}

	if err := s.validateOTP(payload.Email, payload.OTP); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		logging.LogOtpVerification(payload.Email, false)
		return
	}
	logging.LogOtpVerification(payload.Email, true)
	c.JSON(http.StatusOK, gin.H{"message": "OTP verified"})
}

// handleRegister godoc
// @Summary Register a new user
// @Description This endpoint allows new users to register by providing an email, role, and a valid OTP. It automatically generates a password and sends it to the user's email.
// @Tags Users
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "User registration data"
// @Success 201 {object} map[string]string "User created successfully with authentication token"
// @Failure 400 {object} map[string]string "Invalid request payload"
// @Failure 401 {object} map[string]string "Invalid OTP"
// @Failure 409 {object} map[string]string "Email already exists"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router  /api/v1/users/register [post]
func (s *UserService) handleRegister(c *gin.Context) {
	var registerRequest models.RegisterRequest
	if err := c.ShouldBindJSON(&registerRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload"})
		return
	}

	if registerRequest.Role == "" {
		registerRequest.Role = "user"
	}
	if err := validateUserPayload(&registerRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		log.Warn().Msg("Invalid registration payload")
		return
	}

	if err := s.validateOTP(registerRequest.Email, registerRequest.OTP); err != nil {
		log.Warn().Str("otp", registerRequest.OTP).Msg("Invalid OTP passed for email registration")
		c.JSON(http.StatusUnauthorized, gin.H{"message": err.Error()})
		return
	}
	password, err := GenerateRandomPassword()
	if err != nil {
		log.Error().Msg("Error generating password")
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Error generating password"})
		return
	}

	if _, err := sendPasswordEmail(registerRequest.Email, password); err != nil {
		log.Error().Str("email", registerRequest.Email).Msg("Failed to send password email")
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to send password"})
		return
	}

	hashedPassword, err := HashPassword(password)
	if err != nil {
		log.Error().Msg("Error hashing password")
		utility.WriteJSON(c.Writer, http.StatusInternalServerError, "Error creating user", nil)
		return
	}

	newUser := models.User{
		Email:     registerRequest.Email,
		Role:      registerRequest.Role,
		CreatedAt: time.Now(),
		Password:  hashedPassword,
	}
	u, err := s.store.CreateUser(&newUser)
	if err != nil {
		if err == gorm.ErrDuplicatedKey {
			utility.WriteJSON(c.Writer, http.StatusConflict, "Email already exists", nil)
		} else {
			utility.WriteJSON(c.Writer, http.StatusInternalServerError, "Error creating user", nil)
		}
		return
	}

	token, err := createAndSetAuthCookie(u.ID, c.Writer)
	if err != nil {
		utility.WriteJSON(c.Writer, http.StatusInternalServerError, "Error creating user", nil)
		return
	}

	log.Info().Str("email", registerRequest.Email).Msg("User registered successfully")
	utility.WriteJSON(c.Writer, http.StatusCreated, "User created successfully", token)
}

// handleUserLogin godoc
// @Summary User login
// @Description This endpoint allows users to log in using their email or user tag and password. It returns a JWT token upon successful authentication.
// @Tags Users
// @Accept json
// @Produce json
// @Param loginRequest body models.LoginRequest true "Login request data"
// @Success 200 {object} map[string]interface{} "User successfully logged in with JWT token"
// @Failure 400 {object} map[string]string "Invalid request payload"
// @Failure 401 {object} map[string]string "User not found or invalid email/password"
// @Failure 500 {object} map[string]string "Internal server error"
// @Router  /api/v1/users/login [post]
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
		logging.LogLoginAttempt(user.Email, false)
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
	logging.LogLoginAttempt(responseData.Email, true)
	utility.WriteJSON(c.Writer, http.StatusOK, "User login successfully", gin.H{
		"user":  responseData,
		"token": token,
	})
}

// handleChangePassword godoc
// @Summary Change user password
// @Description This endpoint allows an authenticated user to change their password by providing the current password, a new password, and OTP verification.
// @Tags Users
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer Token"
// @Param passwordChangeRequest body models.ChangePasswordRequest true "Password change request data"
// @Success 200 {object} map[string]string "Password changed successfully"
// @Failure 400 {object} map[string]string "Invalid request payload or permission denied"
// @Failure 401 {object} map[string]string "Current password is incorrect or OTP validation failed"
// @Failure 500 {object} map[string]string "Error updating password"
// @Router  /api/v1/users/change-password [post]
func (s *UserService) handleChangePassword(c *gin.Context) {
	userID, exists := c.Get("userID")
	var payload models.ChangePasswordRequest

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
	logging.LogPasswordChange(user.Email)
	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// handleRequestResetPassword godoc
// @Summary Request password reset
// @Description This endpoint allows a user to request a password reset by providing their registered email. An OTP will be sent to the email for further verification.
// @Tags Users
// @Accept json
// @Produce json
// @Param resetRequest body models.RequestResetPasswordRequest true "Password reset request data"
// @Success 200 {object} map[string]string "OTP sent to email"
// @Failure 400 {object} map[string]string "Invalid request payload"
// @Failure 404 {object} map[string]string "User not found"
// @Failure 500 {object} map[string]string "Error generating OTP or sending email"
// @Router  /api/v1/users/request-reset-password [post]
func (s *UserService) handleRequestResetPassword(c *gin.Context) {
	var payload models.RequestResetPasswordRequest

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

	if _, err := sendOTPEmail(user.Email, otp); err != nil {
		utility.RespondWithError(c, http.StatusInternalServerError, "Failed to send OTP")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent to email"})
}

// handleResetPassword godoc
// @Summary Reset user password
// @Description This endpoint allows a user to reset their password by providing their email, OTP, and a new password.
// @Tags Users
// @Accept json
// @Produce json
// @Param resetPasswordRequest body models.ResetPasswordRequest true "Password reset data"
// @Success 200 {object} map[string]string "Password reset successfully"
// @Failure 400 {object} map[string]string "Invalid request payload"
// @Failure 401 {object} map[string]string "Invalid or expired OTP"
// @Failure 404 {object} map[string]string "User not found"
// @Failure 500 {object} map[string]string "Error hashing password or updating user"
// @Router  /api/v1/users/reset-password [post]
func (s *UserService) handleResetPassword(c *gin.Context) {
	var payload models.ResetPasswordRequest

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

var otpStore sync.Map

func (s *UserService) generateAndStoreOTP(email string) (string, error) {
	otp, err := generateOTP()
	expiration := time.Now().Add(10 * time.Minute)
	otpStore.Store(email, OTPData{OTP: otp, ExpiresAt: expiration})
	s.logger.Info().Str("email", email).Str("otp", otp).Msg("Generated and stored OTP")

	return otp, err
}

func (s *UserService) validateOTP(email, providedOTP string) error {
	data, ok := otpStore.Load(email)
	if !ok {
		return fmt.Errorf("otp session expired, please request a new OTP")
	}
	otpData := data.(OTPData)
	if time.Now().After(otpData.ExpiresAt) {
		return fmt.Errorf("your OTP has expired, please request a new one")
	}
	if otpData.OTP != providedOTP {
		return fmt.Errorf("the OTP you entered is incorrect, please try again")
	}
	return nil
}
