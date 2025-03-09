package db

import (
	"fmt"
	"log"
	"os"

	"goExpenses/db/models"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB // Global variable to store DB connection

func ConnectDB() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Read database connection variables
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER") // Changed from "USER" to "DB_USER"
	dbname := os.Getenv("DB_NAME")
	password := os.Getenv("DB_PASSWORD")

	// Construct DSN (Data Source Name)
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Shanghai",
		host, user, password, dbname, port,
	)

	// Open Database Connection
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true, // Disables implicit prepared statement usage
	}), &gorm.Config{})

	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Assign to global variable
	DB = db

	// Automatically migrate the User model
	err = db.AutoMigrate(&models.User{}, &models.Company{}, &models.Expenses{}, &models.Categories{}, &models.Revenue{})
	if err != nil {
		log.Fatal("Failed to migrate User model:", err)
	}

	fmt.Println("Database connected successfully!")
}
