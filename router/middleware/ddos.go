package middleware

import (
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/gin-gonic/gin"
)

type clientStat struct {
	Count      int
	Timestamp  int64
	BannedTill time.Time
}

var (
	clients = make(map[string]*clientStat)
	mu      sync.Mutex
)

const (
	limitPerSecond = 5
	banDuration    = 10 * time.Hour
)

func DDoSFilter() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if isBanned(ip) {
			c.AbortWithStatusJSON(429, gin.H{
				"error": "too many requests",
			})
			return
		}

		c.Next()
	}
}

func isBanned(ip string) bool {
	mu.Lock()
	defer mu.Unlock()

	stat, ok := clients[ip]
	if !ok {
		return false
	}

	return time.Now().Before(stat.BannedTill)
}

func registerInvalid(ip string) {
	now := time.Now().Unix()

	mu.Lock()
	defer mu.Unlock()

	stat, ok := clients[ip]
	if !ok {
		clients[ip] = &clientStat{
			Count:     1,
			Timestamp: now,
		}
		return
	}

	if time.Now().Before(stat.BannedTill) {
		return
	}

	if stat.Timestamp != now {
		stat.Count = 1
		stat.Timestamp = now
		return
	}

	stat.Count++

	if stat.Count > limitPerSecond {
		stat.BannedTill = time.Now().Add(banDuration)

		log.WithField("ip", ip).
			Warn("too many invalid jwt requests - banned til " +
				stat.BannedTill.Format(time.RFC3339))
	}
}
