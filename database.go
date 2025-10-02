package main

import (
	"errors"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/oauth2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// User represents an application user and their OAuth/session info.
type User struct {
	ID   uint `gorm:"primarykey"`
	Name string

	SessionId string

	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
}

// OAuthToken returns the user's OAuth2 token as an oauth2.Token struct.
func (u *User) OAuthToken() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  u.AccessToken,
		TokenType:    u.TokenType,
		RefreshToken: u.RefreshToken,
		Expiry:       u.Expiry,
	}
}

// SetOAuthToken updates the user's OAuth token fields from an oauth2.Token.
func (u *User) SetOAuthToken(token *oauth2.Token) {
	u.AccessToken = token.AccessToken
	u.TokenType = token.TokenType
	u.RefreshToken = token.RefreshToken
	u.Expiry = token.Expiry
}

// UserPublicKeys represents a public SSH key associated with a user.
type UserPublicKeys struct {
	ID        uint `gorm:"primarykey"`
	UserId    uint
	User      User
	Name      string
	PublicKey string `gorm:"uniqueIndex"`
}

// Database wraps the GORM database connection and provides user/key operations.
type Database struct {
	Db *gorm.DB
}

// NewDatabase initializes the database connection and migrates the schema.
func NewDatabase() (*Database, error) {
	// select database driver based on DSN prefix
	var conn gorm.Dialector
	switch strings.Split(strings.ToLower(config.DatabaseUrl), ":")[0] {
	case "file":
		conn = sqlite.Open(config.DatabaseUrl)
	case "postgres":
		conn = postgres.Open(config.DatabaseUrl)
	default:
		return nil, errors.New("unsupported database type, only sqlite and postgres are supported")
	}

	// open database connection
	db, err := gorm.Open(conn, &gorm.Config{})
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

// GetUserBySessionId fetches a user by their session ID.
func (db *Database) GetUserBySessionId(sessionId string) (*User, error) {
	var user User
	if err := db.Db.Where("session_id = ?", sessionId).Limit(1).Find(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// GetUser fetches a user by their name.
func (db *Database) GetUser(name string) (*User, error) {
	var user User
	if err := db.Db.Where("name = ?", name).Limit(1).Find(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateUser creates a new user with the given name.
func (db *Database) CreateUser(name string) (*User, error) {
	user := &User{Name: name}
	if err := db.Db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

// GetPublicKeysOfUser returns all public keys associated with the user.
func (db *Database) GetPublicKeysOfUser(user *User) ([]UserPublicKeys, error) {
	var keys []UserPublicKeys
	if err := db.Db.Where("user_id = ?", user.ID).Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

// AddPublicKeyToUser adds a new public key for the user.
func (db *Database) AddPublicKeyToUser(user *User, name string, key string) error {
	publicKey := &UserPublicKeys{
		UserId:    user.ID,
		Name:      name,
		PublicKey: key,
	}
	return db.Db.Create(publicKey).Error
}

// CheckPublicKeyForUserName checks if a public key is valid for the given user name.
func (db *Database) CheckPublicKeyForUserName(userName string, key string) (bool, error) {
	var publicKey UserPublicKeys
	if err := db.Db.Joins("JOIN users ON users.id = user_public_keys.user_id").
		Where("users.name = ? AND user_public_keys.public_key = ?", userName, key).
		Limit(1).Find(&publicKey).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
