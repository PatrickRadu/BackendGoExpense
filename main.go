package main

import (
	"goExpenses/db"
	"goExpenses/db/models"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

func init() {
	db.ConnectDB()
}

func main() {
	e := echo.New()
	SECRET := os.Getenv("SECRET")

	r := e.Group("/api")
	r.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey: []byte(SECRET),
	}))
	e.POST("/register", Register)
	e.POST("/login", Login)
	r.GET("", func(c echo.Context) error {
		return c.JSON(200, "Hello, World!")
	})
	r.GET("/company", GetCompany)
	r.POST("/revenues", CreateRevenue)
	r.GET("/revenues", getRevenues)
	r.GET("/revenues/:id", getARevenue)
	r.POST("/expenses", CreateExpense)
	r.GET("/categories", getCategories)
	r.DELETE("/categories/:id", deleteCategory)
	r.GET("/expenses", getExpenses)
	r.GET("/expenses/:id", getAExpense)
	r.GET("/expenses/date", getExpensesBasedOnDate)
	r.PUT("/company", changeCompany)
	e.Logger.Fatal(e.Start(":1323"))

}

func deleteCategory(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))
	categoryID := c.Param("id")
	var category models.Categories
	err := db.DB.Where("id = ? and company_id = ?", categoryID, companyID).First(&category).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to fetch category"})
	}
	err = db.DB.Delete(&category).Error
	return c.JSON(200, map[string]string{"message": "Category deleted successfully"})
}

func getExpensesBasedOnDate(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))
	period := c.QueryParam("period")
	var expenses []models.Expenses
	if period == "last_month" {
		err := db.DB.Where("company_id = ? and created_at > ?", companyID, time.Now().AddDate(0, -1, 0)).Preload("Categories").Find(&expenses).Error
		if err != nil {
			return c.JSON(400, map[string]string{"error": "Failed to fetch expenses"})
		}
	}
	if period == "last_3_months" {
		err := db.DB.Where("company_id = ? and created_at > ?", companyID, time.Now().AddDate(0, -3, 0)).Preload("Categories").Find(&expenses).Error
		if err != nil {
			return c.JSON(400, map[string]string{"error": "Failed to fetch expenses"})
		}
	}
	if period == "last_6_months" {
		err := db.DB.Where("company_id = ? and created_at > ?", companyID, time.Now().AddDate(0, -6, 0)).Preload("Categories").Find(&expenses).Error
		if err != nil {
			return c.JSON(400, map[string]string{"error": "Failed to fetch expenses"})
		}
	}
	if period == "last_year" {
		err := db.DB.Where("company_id = ? and created_at > ?", companyID, time.Now().AddDate(-1, 0, 0)).Preload("Categories").Find(&expenses).Error
		if err != nil {
			return c.JSON(400, map[string]string{"error": "Failed to fetch expenses"})
		}
	}
	type CategResp struct {
		Name       string  `json:"name"`
		Amount     float64 `json:"amount"`
		Categories []struct {
			Name string `json:"name"`
		} `json:"categories"`
	}
	var expensesResp []CategResp
	for _, expense := range expenses {
		var categoriesExp []struct {
			Name string `json:"name"`
		}
		for _, category := range expense.Categories {
			categoriesExp = append(categoriesExp, struct {
				Name string `json:"name"`
			}{
				Name: category.Name,
			})
		}
		expensesResp = append(expensesResp, CategResp{
			Name:       expense.Name,
			Amount:     expense.Amount,
			Categories: categoriesExp,
		})
	}
	return c.JSON(200, expensesResp)
}

func changeCompany(c echo.Context) error {
	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))

	var input struct {
		Name     string `json:"name"`
		Tax      string `json:"tax"`
		Dividend string `json:"dividend"`
	}

	var company models.Company
	if err := db.DB.First(&company, companyID).Error; err != nil {
		return c.JSON(400, map[string]string{"error": "Company not found"})
	}
	company.Name = input.Name
	company.Tax = input.Tax
	company.Dividend = input.Dividend
	err := db.DB.Save(&company)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to update company"})
	}
	return c.JSON(200, company)
}

func getAExpense(c echo.Context) error {
	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))

	expenseID := c.Param("id")
	var expense models.Expenses
	err := db.DB.Where("id = ? AND company_id = ?", expenseID, companyID).Preload("Company").Preload("Categories").First(&expense).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to fetch expense"})
	}
	var ExpenseResponse struct {
		Name       string  `json:"name"`
		Amount     float64 `json:"amount"`
		Categories []struct {
			Name string `json:"name"`
		} `json:"categories"`
		Company struct {
			Name string `json:"name"`
			Tax  string `json:"tax"`
		} `json:"company"`
	}
	ExpenseResponse.Name = expense.Name
	ExpenseResponse.Amount = expense.Amount
	for _, category := range expense.Categories {
		ExpenseResponse.Categories = append(ExpenseResponse.Categories, struct {
			Name string `json:"name"`
		}{
			Name: category.Name,
		})
	}
	ExpenseResponse.Company.Name = expense.Company.Name
	ExpenseResponse.Company.Tax = expense.Company.Tax
	return c.JSON(200, ExpenseResponse)
}

func getARevenue(c echo.Context) error {
	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))
	revenueID := c.Param("id")
	var revenue models.Revenue
	err := db.DB.Where("id = ? and company_id = ?", revenueID, companyID).Preload("Company").First(&revenue).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to fetch revenue"})
	}
	var response struct {
		Name        string  `json:"name"`
		Amount      float64 `json:"amount"`
		CompanyName string  `json:"company_name"`
	}
	response.Name = revenue.Name
	response.Amount = revenue.Amount
	response.CompanyName = revenue.Company.Name
	return c.JSON(200, response)
}

func getExpenses(c echo.Context) error {
	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))

	var expenses []models.Expenses
	err := db.DB.Where("company_id=?", companyID).Preload("Categories").Find(&expenses).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to fetch expenses"})
	}

	type CategResp struct {
		Name string `json:"name"`
		ID   uint   `json:"categoryId"`
	}
	type ExpenseResponse struct {
		Name       string      `json:"name"`
		Amount     float64     `json:"amount"`
		Categories []CategResp `json:categories`
		ID         uint        `json:expenseId`
	}

	var expensesResp []ExpenseResponse
	for _, expense := range expenses {
		var categoriesExp []CategResp
		for _, category := range expense.Categories {
			categoriesExp = append(categoriesExp, CategResp{
				Name: category.Name,
				ID:   category.ID,
			})
		}
		expensesResp = append(expensesResp, ExpenseResponse{
			Name:       expense.Name,
			Amount:     expense.Amount,
			Categories: categoriesExp,
			ID:         expense.ID,
		})
	}
	return c.JSON(200, expensesResp)
}

func GetCompany(c echo.Context) error {

	userToken := c.Get("user").(*jwt.Token)
	claims := userToken.Claims.(jwt.MapClaims)
	userID := uint(claims["id"].(float64)) // Convert float64 to uint

	var user models.User
	err := db.DB.Preload("Company").Where("id = ?", userID).First(&user).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "User or company not found"})
	}

	return c.JSON(200, user.Company)
}

func CreateExpense(c echo.Context) error {
	userToken, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return c.JSON(400, map[string]string{"error": "Invalid user"})
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return c.JSON(400, map[string]string{"error": "Invalid user"})
	}
	companyID := uint(claims["company_id"].(float64))
	if !ok {
		return c.JSON(400, map[string]string{"error": "Invalid user"})
	}
	var input struct {
		Name       string   `json:"name"`
		Amount     float64  `json:"amount"`
		Categories []string `json:"categories"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request data"})
	}

	var categories []models.Categories
	for _, category := range input.Categories {
		categories = append(categories, models.Categories{Name: category, CompanyID: companyID})
	}

	expense := models.Expenses{
		Name:       input.Name,
		Amount:     input.Amount,
		Categories: categories,
		CompanyID:  companyID,
	}

	err := db.DB.Create(&expense).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to create expense"})
	}
	return c.JSON(200, expense)
}

func getCategories(c echo.Context) error {
	userToken, ok := c.Get("user").(*jwt.Token)
	if !ok {
		return c.JSON(400, map[string]string{"error": "Invalid user"})
	}
	claims, ok := userToken.Claims.(jwt.MapClaims)
	if !ok {
		return c.JSON(400, map[string]string{"error": "Invalid user"})
	}
	companyID := uint(claims["company_id"].(float64))

	var categories []models.Categories
	err := db.DB.Where("company_id = ?", companyID).Find(&categories).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to fetch categories"})
	}
	type responseCat struct {
		Name string `json:"name"`
		Id   uint   `json:"id"`
	}

	var responseCategories []responseCat

	for _, category := range categories {
		responseCategories = append(responseCategories, responseCat{
			Name: category.Name,
			Id:   category.ID,
		})
	}

	return c.JSON(200, responseCategories)
}

func CreateRevenue(c echo.Context) error {
	var input struct {
		Name   string  `json:"name"`
		Amount float64 `json:"amount"`
	}
	if err := c.Bind(&input); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request data"})
	}

	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))

	revenue := models.Revenue{
		Name:      input.Name,
		Amount:    input.Amount,
		CompanyID: companyID,
	}

	err := db.DB.Create(&revenue).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to create revenue"})
	}

	response := struct {
		Name      string  `json:"name"`
		Amount    float64 `json:"amount"`
		CompanyId uint    `json:"company_id"`
	}{
		Name:      revenue.Name,
		Amount:    revenue.Amount,
		CompanyId: revenue.CompanyID,
	}

	return c.JSON(200, response)
}

func getRevenues(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	companyID := uint(claims["company_id"].(float64))

	var revenues []models.Revenue
	err := db.DB.Where("company_id = ?", companyID).Preload("Company").Find(&revenues).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to fetch revenues"})
	}

	type response struct {
		Name        string  `json:"name"`
		Amount      float64 `json:"amount"`
		CompanyName string  `json:"company_name"`
	}

	var responseRevenues []response
	for _, revenue := range revenues {
		responseRevenues = append(responseRevenues, response{
			Name:        revenue.Name,
			Amount:      revenue.Amount,
			CompanyName: revenue.Company.Name,
		})
	}

	return c.JSON(200, responseRevenues)
}

func Register(c echo.Context) error {
	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Company  struct {
			Name     string `json:"name"`
			Tax      string `json:"tax"`
			Dividend string `json:"dividend"`
		} `json:"company"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request data"})
	}

	newCompany := models.Company{
		Name:     input.Company.Name,
		Tax:      input.Company.Tax,
		Dividend: input.Company.Dividend,
	}

	err := db.DB.Create(&newCompany).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to create company"})
	}

	hash, err := HashPassword(input.Password)
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Password hashing failed"})
	}

	user := models.User{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: hash,
		CompanyID:    newCompany.ID,
	}

	err = db.DB.Create(&user).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "Failed to create user"})
	}

	return c.JSON(200, user)
}

func Login(c echo.Context) error {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.Bind(&input); err != nil {
		return c.JSON(400, map[string]string{"error": "Invalid request data"})
	}

	var user models.User
	err := db.DB.Where("email = ?", input.Email).First(&user).Error
	if err != nil {
		return c.JSON(400, map[string]string{"error": "User not found"})
	}

	if !CheckpasswordHash(input.Password, user.PasswordHash) {
		return c.JSON(400, map[string]string{"error": "Invalid password"})
	}

	SECRET := os.Getenv("SECRET")
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":         user.ID,
		"name":       user.Name,
		"email":      user.Email,
		"company_id": user.CompanyID,
		"exp":        time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(SECRET))
	if err != nil {
		return c.JSON(500, map[string]string{"error": "Failed to generate token"})
	}

	// ✅ Return token in response
	return c.JSON(200, map[string]string{
		"token": tokenString,
	})
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckpasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
