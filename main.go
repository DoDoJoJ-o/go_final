package main

import (
	"fmt"
	"go_final/controller"
	"go_final/model"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {

	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
	fmt.Println(viper.Get("mysql.dsn"))
	dsn := viper.GetString("mysql.dsn")
	dialactor := mysql.Open(dsn)
	db, err := gorm.Open(dialactor) // Declaration of db connection
	if err != nil {
		panic(err)
	}
	fmt.Println("Connection successful")

	customer := []model.Customer{}
	result := db.Find(&customer)
	if result.Error != nil {
		panic(result.Error)
	}
	fmt.Println(customer)

	router := gin.Default()
	controller.SetupRoutes(router, db)
	router.Run()
}
