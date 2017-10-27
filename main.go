package main

import (
	"encoding/base64"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// PostBody ... Bind from JSON and FormPost
type PostBody struct {
	Message string `form:"message" json:"message"`
}

func basicAuth(ctx *gin.Context) (username, password string, ok bool) {
	auth := ctx.Request.Header.Get("Authorization")
	if auth == "" {
		return
	}
	return parseBasicAuth(string(auth))
}

func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}

// BasicAuth ... simple authorization
func BasicAuth() gin.HandlerFunc {

	return func(ctx *gin.Context) {

		var (
			requiredUser     = "user"
			requiredPassword = "pass"
		)

		user, password, hasAuth := basicAuth(ctx)

		if hasAuth && user == requiredUser && password == requiredPassword {
			ctx.Next()
			return
		}
		ctx.Header("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
		ctx.AbortWithStatus(http.StatusUnauthorized)
	}
}

func main() {
	server := gin.Default()

	server.GET("/noauth", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	server.GET("/noauth/rand", func(ctx *gin.Context) {
		codes := []int{200, 203, 404, 400, 500, 502, 302}
		rand.Seed(time.Now().UTC().UnixNano())
		code := rand.Intn(6)
		ctx.JSON(codes[code], gin.H{"status code": codes[code]})
	})

	auth := server.Group("/auth")
	{
		auth.Use(BasicAuth())

		auth.GET("", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
		})

		auth.POST("", func(ctx *gin.Context) {
			var json PostBody
			if err := ctx.BindJSON(&json); err != nil {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			}
			ctx.String(http.StatusCreated, "")
		})

		auth.POST("/redirect", func(ctx *gin.Context) {
			var json PostBody
			if err := ctx.BindJSON(&json); err != nil {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			}
			ctx.Redirect(http.StatusMovedPermanently, "/auth")
		})

		auth.DELETE("/:id", func(ctx *gin.Context) {
			id := ctx.Param("id")
			ctx.JSON(http.StatusOK, gin.H{"id": id, "deleted": true})
		})

		auth.PUT("/:id", func(ctx *gin.Context) {
			id := ctx.Param("id")
			var json PostBody
			if err := ctx.BindJSON(&json); err != nil {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			} else {
				ctx.JSON(http.StatusOK, gin.H{"id": id, "replaced": true, "message": json.Message})
			}
		})

		auth.PATCH("/:id", func(ctx *gin.Context) {
			id := ctx.Param("id")
			var json PostBody
			if err := ctx.BindJSON(&json); err != nil {
				ctx.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"message": err.Error()})
			} else {
				ctx.JSON(http.StatusOK, gin.H{"id": id, "updated": true, "message": json.Message})
			}
		})
	}

	server.GET("/generic/*action", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	server.POST("/generic/*action", func(ctx *gin.Context) {
		ctx.String(http.StatusCreated, "")
	})

	server.Run(":8091")
}
