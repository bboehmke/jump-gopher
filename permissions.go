package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"
)

type Permissions struct {
	permissions map[string]*Permission
	mutex       sync.RWMutex
}

type Permission struct {
	Allow []string
	Deny  []string

	allowRegex *regexp.Regexp
	denyRegex  *regexp.Regexp
}

func NewPermissions() (*Permissions, error) {
	config := &Permissions{}

	err := config.load()
	if err != nil {
		return nil, err
	}

	lastStat, err := os.Stat("permissions.yml")
	if err != nil {
		return nil, fmt.Errorf("could not stat config.yml: %w", err)
	}

	go func() {
		for {
			time.Sleep(1 * time.Second)

			stat, err := os.Stat("permissions.yml")
			if err != nil {
				continue
			}

			if stat.Size() != lastStat.Size() || stat.ModTime() != lastStat.ModTime() {
				err := config.load()
				if err != nil {
					log.Printf("error reloading config: %v", err)
				} else {
					lastStat = stat
				}
			}
		}
	}()

	return config, nil
}

func (c *Permissions) load() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	file, err := os.Open("permissions.yml")
	if err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}
	defer file.Close()

	var conf map[string]*Permission
	err = yaml.NewDecoder(file).Decode(&conf)
	if err != nil {
		return fmt.Errorf("error parsing config file: %w", err)
	}

	failed := false
	for name, perm := range conf {
		perm.allowRegex, err = buildRegex(perm.Allow)
		if err != nil {
			log.Printf("%s: invalid allow regex: %v", name, err)
			failed = true
		}
		perm.denyRegex, err = buildRegex(perm.Deny)
		if err != nil {
			log.Printf("%s: invalid deny regex: %v", name, err)
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("regexp validation failed")
	}

	c.permissions = conf
	log.Print("config successfully loaded")
	return nil
}

func buildRegex(patterns []string) (*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	regexStr := "^(" + strings.Join(patterns, ")|(") + ")$"
	compile, err := regexp.Compile(regexStr)
	if err != nil {
		return nil, fmt.Errorf("error compiling regex '%s': %w", regexStr, err)
	}
	return compile, nil
}

func (c *Permissions) CheckPermission(name, addr string) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	perm, ok := c.permissions[name]
	if !ok {
		return false
	}
	if perm.denyRegex != nil && perm.denyRegex.MatchString(addr) {
		return false
	}
	if perm.allowRegex != nil && perm.allowRegex.MatchString(addr) {
		return true
	}
	return false
}

func (c *Permissions) GetUserPermissions(name string) *Permission {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	perm, ok := c.permissions[name]
	if !ok {
		// deny all if user not found
		return &Permission{
			Deny: []string{".*"},
		}
	}
	return perm
}
