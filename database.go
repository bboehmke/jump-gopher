package main

import (
	"errors"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/oauth2"
	_ "gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	ID   uint `gorm:"primarykey"`
	Name string

	SessionId string

	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
}

func (u *User) OAuthToken() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  u.AccessToken,
		TokenType:    u.TokenType,
		RefreshToken: u.RefreshToken,
		Expiry:       u.Expiry,
	}
}

func (u *User) SetOAuthToken(token *oauth2.Token) {
	u.AccessToken = token.AccessToken
	u.TokenType = token.TokenType
	u.RefreshToken = token.RefreshToken
	u.Expiry = token.Expiry
}

type UserPublicKeys struct {
	ID        uint `gorm:"primarykey"`
	UserId    uint
	User      User
	Name      string
	PublicKey string `gorm:"uniqueIndex"`
}

type Database struct {
	Db *gorm.DB
}

func NewDatabase() (*Database, error) {
	db, err := gorm.Open(sqlite.Open(config.DatabaseUrl), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Migrate the schema
	err = db.AutoMigrate(&User{}, &UserPublicKeys{})
	if err != nil {
		return nil, err
	}

	return &Database{Db: db}, nil
}

func (db *Database) GetUserBySessionId(sessionId string) (*User, error) {
	var user User
	if err := db.Db.Where("session_id = ?", sessionId).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *Database) GetUser(name string) (*User, error) {
	var user User
	if err := db.Db.Where("name = ?", name).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *Database) CreateUser(name string) (*User, error) {
	user := &User{Name: name}
	if err := db.Db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func (db *Database) GetPublicKeysOfUser(user *User) ([]UserPublicKeys, error) {
	var keys []UserPublicKeys
	if err := db.Db.Where("user_id = ?", user.ID).Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

func (db *Database) AddPublicKeyToUser(user *User, name string, key string) error {
	publicKey := &UserPublicKeys{
		UserId:    user.ID,
		Name:      name,
		PublicKey: key,
	}
	return db.Db.Create(publicKey).Error
}

func (db *Database) CheckPublicKeyForUserName(userName string, key string) (bool, error) {
	var publicKey UserPublicKeys
	if err := db.Db.Joins("JOIN users ON users.id = user_public_keys.user_id").
		Where("users.name = ? AND user_public_keys.public_key = ?", userName, key).
		First(&publicKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
