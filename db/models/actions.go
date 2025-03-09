package models

import "gorm.io/gorm"

type Expenses struct {
	gorm.Model `query:id`
	Name       string       `json:"name"`
	Amount     float64      `json:"amount"`
	Categories []Categories `json:"categories" gorm:"many2many:expense_categories"`
	CompanyID  uint         `json:"company_id"`
	Company    Company      `json:"company" gorm:"foreignKey:CompanyID"`
}

type Categories struct {
	gorm.Model
	Name      string     `json:"name"`
	CompanyID uint       `json:"company_id"`
	Company   Company    `json:"company" gorm:"foreignKey:CompanyID"`
	Expenses  []Expenses `json:"expenses" gorm:"many2many:expense_categories"`
}

type Revenue struct {
	gorm.Model
	Name      string  `json:"name"`
	Amount    float64 `json:"amount"`
	CompanyID uint    `json:"company_id"`
	Company   Company `json:"company" gorm:"foreignKey:CompanyID"`
}
