package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Name         string  `json:"name"`
	Email        string  `json:"email" gorm:"unique"`
	PasswordHash string  `json:"password"`
	CompanyID    uint    `json:"company_id"`
	Company      Company `json:"company" gorm:"foreignKey:CompanyID"`
}

type Company struct {
	gorm.Model
	Name       string       `json:"name"`
	Tax        string       `json:"tax"`
	Dividend   string       `json:"dividend"`
	Expenses   []Expenses   `json:"expenses" gorm:"foreignKey:CompanyID"`
	Revenues   []Revenue    `json:"revenues" gorm:"foreignKey:CompanyID"`
	Categories []Categories `json:"categories" gorm:"foreignKey:CompanyID"`
}
