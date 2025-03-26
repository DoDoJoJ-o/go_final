package controller

import (
	"go_final/model"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

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

	// Generate JWT token (you'll need to implement token generation)
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

// Helper function to generate JWT token
func generateJWTToken(customer model.Customer) (string, error) {
	// Implement JWT token generation logic
	// This is a placeholder - you'll need to use a JWT library like golang-jwt/jwt
	return "", nil
}

// Utility function to hash password (for registration)
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}
