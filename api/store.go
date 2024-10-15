package api

import (
	"fmt"
	"nexvenue/internal/models"
	"time"

	"github.com/google/uuid"
	"golang.org/x/exp/rand"
	"gorm.io/gorm"
)

type Store interface {
	CreateUser(user *models.User) (*models.User, error)
	FindUserByEmail(email string, user *models.User) error
	FindUserByID(userID string) (*models.User, error)
	UpdateUser(user *models.User) error
	GetAllUsers() ([]models.User, error)
}

type Storage struct {
	db *gorm.DB
}

func NewStore(db *gorm.DB) *Storage {
	return &Storage{
		db: db,
	}
}

func (s *Storage) CreateUser(user *models.User) (*models.User, error) {
	if user.Role == "" {
		user.Role = "user"
	}
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UserTag = s.generateUniqueUserTag(user.FirstName, user.LastName, user.Email)
	if err := s.db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Storage) generateUniqueUserTag(firstName, lastName, email string) string {
	var baseTag string

	// Use firstName and lastName if provided
	if firstName != "" && lastName != "" {
		baseTag = fmt.Sprintf("%s.%s", firstName, lastName)
	} else {
		// Fallback to email, but strip the domain part
		baseTag = StripEmailDomain(email)
	}

	if len(baseTag) < 6 {
		baseTag += RandomString(6 - len(baseTag))
	}
	var user models.User
	userTag := baseTag

	for {
		err := s.db.Where("user_tag = ?", userTag).First(&user).Error
		if err == gorm.ErrRecordNotFound {
			break
		}
		userTag = fmt.Sprintf("%s%d", baseTag, rand.Intn(1000))
	}
	return userTag
}

func (db *Storage) FindUserByEmail(email string, user *models.User) error {
	return db.db.Where("email = ?", email).First(user).Error
}

func (s *Storage) FindUserByEmailOrUserTag(emailOrUserTag string, user *models.User) error {
	return s.db.Where("email = ? OR user_tag = ?", emailOrUserTag, emailOrUserTag).First(user).Error
}

func (s *Storage) FindUserByID(userID string) (*models.User, error) {
	var user models.User
	if err := s.db.Where("id = ?", userID).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *Storage) UpdateUser(user *models.User) error {
	return s.db.Save(user).Error
}

func (s *Storage) GetAllUsers() ([]models.User, error) {
	var users []models.User
	if err := s.db.Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
