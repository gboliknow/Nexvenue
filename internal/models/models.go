package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID        string         `gorm:"primaryKey"`
	Email     string         `gorm:"type:varchar(255);unique;not null"`
	UserTag        string         `gorm:"type:varchar(50);unique;not null"` //
	FirstName string         `gorm:"type:varchar(255);not null"`
	LastName  string         `gorm:"type:varchar(255);not null"`
	Password  string         `gorm:"type:varchar(255);not null"`
	Role      string         `gorm:"type:varchar(50);not null"`
	ProfilePicture string         `gorm:"type:varchar(255)"`   
	IsVerified     bool           `gorm:"default:false"`       
	Bio            string         `gorm:"type:varchar(500)"`
	CreatedAt time.Time      `gorm:"index"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
	Phone     string         `gorm:"type:varchar(20)"`
	Address   string         `gorm:"type:varchar(255)"`
}

type UserResponse struct {
	ID        string         `gorm:"primaryKey"`
	Email     string         `gorm:"type:varchar(255);unique;not null"`
	FirstName string         `gorm:"type:varchar(255);not null"`
	LastName  string         `gorm:"type:varchar(255);not null"`
	Role      string         `gorm:"type:varchar(50);not null"`
	ProfilePicture string         `gorm:"type:varchar(255)"`   
	IsVerified     bool           `gorm:"default:false"`       
	Bio            string         `gorm:"type:varchar(500)"`
	CreatedAt time.Time      `gorm:"index"`
	DeletedAt gorm.DeletedAt `gorm:"index"`
	Phone     string         `gorm:"type:varchar(20)"`
	Address   string         `gorm:"type:varchar(255)"`
}

type Response struct {
	StatusCode int         `json:"statusCode"`
	Message    string      `json:"message"`
	Data       interface{} `json:"data,omitempty"` // Data is omitted if nil or empty
}

func (user *User) BeforeCreate(tx *gorm.DB) (err error) {
	user.ID = uuid.New().String()
	return
}

