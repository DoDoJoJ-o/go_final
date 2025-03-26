package controller

import (
	"go_final/model"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// JWT Secret Key (in a real application, this should be stored securely and not hardcoded)
var jwtSecretKey = []byte("your_secret_key_here")

type LoginController struct {
	DB *gorm.DB
}

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	CustomerID int    `json:"customer_id"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
	Email      string `json:"email"`
	Token      string `json:"token,omitempty"`
}

func NewLoginController(db *gorm.DB) *LoginController {
	return &LoginController{DB: db}
}

func (lc *LoginController) Login(c *gin.Context) {
	var loginReq LoginRequest

	// Validate input
	if err := c.ShouldBindJSON(&loginReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid input",
			"details": err.Error(),
		})
		return
	}

	// Find customer by email
	var customer model.Customer
	result := lc.DB.Where("email = ?", loginReq.Email).First(&customer)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	// Compare passwords
	err := bcrypt.CompareHashAndPassword([]byte(customer.Password), []byte(loginReq.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid credentials",
		})
		return
	}

	// Generate JWT token
	token, err := generateJWTToken(customer)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Could not generate authentication token",
		})
		return
	}

	// Prepare response
	response := LoginResponse{
		CustomerID: customer.CustomerID,
		FirstName:  customer.FirstName,
		LastName:   customer.LastName,
		Email:      customer.Email,
		Token:      token,
	}

	c.JSON(http.StatusOK, response)
}

// Generate JWT Token
func generateJWTToken(customer model.Customer) (string, error) {
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"customer_id": customer.CustomerID,
		"email":       customer.Email,
		"exp":         time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	})

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(jwtSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Utility function to hash password (for registration)
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Middleware to validate JWT token
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization token is missing",
			})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		// Parse token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecretKey, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token",
			})
			c.Abort()
			return
		}

		// Verify token claims
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// You can add additional verification if needed
			c.Set("customer_id", claims["customer_id"])
			c.Set("email", claims["email"])
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid token claims",
			})
			c.Abort()
		}
	}
}

// Example router setup
func SetupRoutes(r *gin.Engine, db *gorm.DB) {
	loginController := NewLoginController(db)

	// Public routes
	r.POST("/login", loginController.Login)

	// Protected routes example
	protectedRoutes := r.Group("/")
	protectedRoutes.Use(AuthMiddleware())
	{
		// Add protected routes here
		// Example: protectedRoutes.GET("/profile", getProfileHandler)
	}
}
