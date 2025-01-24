package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var usersCollection *mongo.Collection
var ctx = context.Background()

const jwtSecret = "06df829c80fa7a07d6b4e219a0ea683dacb6cf6f652db490417893179adf5525"

// Whale represents the whale model
type Whale struct {
	ID              primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Name            string             `json:"name"`
	DietType        string             `json:"dietType"`
	Size            float64            `json:"size"`
	Habitat         string             `json:"habitat"`
	PopulationCount int                `json:"populationCount"`
}

type User struct {
	Username          string `bson:"username"`
	HashedPassword    string `bson:"hashedPassword"`
	Role              string `bson:"role"`
	Confirmed         bool   `bson:"confirmed"`
	ConfirmationToken string `bson:"confirmationToken"`
}

type SupportMessage struct {
	Subject    string `json:"subject"`
	Message    string `json:"message"`
	Email      string `json:"email"`
	Attachment string
}

func register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if len(username) < 8 || len(password) < 8 {
		http.Error(w, "Username and password must be at least 8 characters", http.StatusNotAcceptable)
		return
	}

	if !isValidEmail(username) {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}

	var existingUser User
	err := usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&existingUser)
	if err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}

	confirmationToken := generateToken()

	newUser := User{
		Username:          username,
		HashedPassword:    hashedPassword,
		Role:              "user",
		Confirmed:         false,
		ConfirmationToken: confirmationToken,
	}
	_, err = usersCollection.InsertOne(ctx, newUser)
	if err != nil {
		http.Error(w, "Error registering user", http.StatusInternalServerError)
		return
	}

	go sendConfirmationEmail(username, confirmationToken)
	fmt.Fprintln(w, "Registration successful! Please check your email to confirm your account.")
}

func isValidEmail(email string) bool {
	regex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	re := regexp.MustCompile(regex)
	return re.MatchString(email)
}

func confirmEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	var user User
	err := usersCollection.FindOneAndUpdate(
		ctx,
		bson.M{"confirmationToken": token},
		bson.M{"$set": bson.M{"confirmed": true, "confirmationToken": ""}},
	).Decode(&user)

	if err != nil {
		log.Printf("Confirmation failed: token '%s' not found or expired.", token)
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	log.Printf("Email confirmed for username '%s'.", user.Username)
	fmt.Fprintln(w, "Email confirmed successfully! You can now log in.")
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var user User
	err := usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err != nil {
		log.Printf("Login failed: user not found for username '%s'.", username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if !user.Confirmed {
		log.Printf("Login failed: email not confirmed for username '%s'.", username)
		http.Error(w, "Email not confirmed. Please check your email.", http.StatusUnauthorized)
		return
	}

	if !checkPassword(password, user.HashedPassword) {
		log.Printf("Login failed: incorrect password for username '%s'.", username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := generateJWT(user.Username, user.Role)
	if err != nil {
		log.Printf("Error generating token for username '%s': %v", username, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "Authorization",
		Value:   token,
		Expires: time.Now().Add(24 * time.Hour),
	})

	log.Printf("Login successful for username '%s'.", username)
	fmt.Fprintln(w, "Login successful!")
}

func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "Authorization",
		Value:   "",
		Expires: time.Now().Add(-1 * time.Hour),
	})
	fmt.Fprintln(w, "Logout successful!")
}

func protected(w http.ResponseWriter, r *http.Request) {
	tokenCookie, err := r.Cookie("Authorization")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	username, role, err := validateJWT(tokenCookie.Value)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "Welcome, %s! Your role is: %s.", username, role)
}

func generateToken() string {
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	return hex.EncodeToString(token)
}

func sendConfirmationEmail(email, token string) {
	from := "fergumz.70@gmail.com"
	password := "cxnfodqgjvbwufsn"
	to := []string{email}
	subject := "Confirm your registration"
	body := fmt.Sprintf("Click the link to confirm your registration: http://localhost:8080/api/confirm?token=%s", token)

	msg := fmt.Sprintf("From: %s\nTo: %s\nSubject: %s\n\n%s", from, strings.Join(to, ","), subject, body)
	auth := smtp.PlainAuth("", from, password, "smtp.gmail.com")

	err := smtp.SendMail("smtp.gmail.com:587", auth, from, to, []byte(msg))
	if err != nil {
		log.Printf("Error sending email: %v", err)
	}
}

func generateJWT(username, role string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func validateJWT(tokenString string) (string, string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["username"].(string), claims["role"].(string), nil
	}
	return "", "", err
}

func sendMailSimpleHTML(subject, message string, to []string) error {
	headers := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";"
	msg := "Subject: " + subject + "\n" + headers + "\n\n" + message

	auth := smtp.PlainAuth(
		"",
		"fergumz.70@gmail.com",
		"cxnfodqgjvbwufsn",
		"smtp.gmail.com",
	)

	return smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"fergumz.70@gmail.com",
		to,
		[]byte(msg),
	)
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Parse form data
		err := r.ParseMultipartForm(10 << 20) // 10 MB max
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		// Get subject and message
		subject := r.FormValue("subject")
		message := r.FormValue("message")

		// Handle image upload (optional)
		file, header, err := r.FormFile("image")
		if err == nil && header != nil {
			defer file.Close()
			dst, err := os.Create("./static/" + header.Filename) // Save image in static folder
			if err != nil {
				http.Error(w, "Unable to save file", http.StatusInternalServerError)
				return
			}
			defer dst.Close()
			io.Copy(dst, file)

			// Add image to the email message
			message += fmt.Sprintf("<br><img src='/static/%s' alt='Uploaded Image'>", header.Filename)
		}

		// Send email
		err = sendMailSimpleHTML(subject, message, []string{"fergumz.70@gmail.com"})
		if err != nil {
			http.Error(w, "Failed to send email: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "Email sent successfully!")
		return
	}

	// Render form
	tmpl, err := template.ParseFiles("form")
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		log.Println("Template parsing error:", err)
		return
	}
	tmpl.Execute(w, nil)
}

func createWhaleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var whale Whale
	if err := json.NewDecoder(r.Body).Decode(&whale); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	if whale.Name == "" || whale.DietType == "" || whale.Habitat == "" || whale.Size <= 0 || whale.PopulationCount < 0 {
		http.Error(w, "All fields are required and must have valid values", http.StatusBadRequest)
		return
	}

	collection := client.Database("example_db").Collection("whales")
	_, err := collection.InsertOne(context.TODO(), whale)

	if err != nil {
		http.Error(w, "Failed to create whale record", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Whale created successfully"})
}

func getWhalesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	collection := client.Database("example_db").Collection("whales")
	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch whale records", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		http.Error(w, "Failed to parse whale records", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

func deleteWhale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE method is allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	collection := client.Database("example_db").Collection("whales")
	_, err = collection.DeleteOne(context.TODO(), bson.M{"_id": objID})
	if err != nil {
		http.Error(w, "Failed to delete whale", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Whale deleted successfully"})
}

func updateWhale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	var whale Whale
	if err := json.NewDecoder(r.Body).Decode(&whale); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	collection := client.Database("example_db").Collection("whales")
	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": objID}, bson.M{"$set": whale})
	if err != nil {
		http.Error(w, "Failed to update whale", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Whale updated successfully"})
}

func filterWhalesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получение параметров фильтрации
	dietType := r.URL.Query().Get("dietType")
	size := r.URL.Query().Get("size")
	habitat := r.URL.Query().Get("habitat")
	population := r.URL.Query().Get("population")

	// Формирование фильтра
	filter := bson.M{}
	if dietType != "" && dietType != "doesn't matter" {
		filter["dietType"] = dietType
	}
	if size != "" && size != "doesn't matter" {
		switch size {
		case "large":
			filter["size"] = bson.M{"$gte": 20} // Пример: больше 20 метров
		case "middle":
			filter["size"] = bson.M{"$gte": 10, "$lt": 20}
		case "small":
			filter["size"] = bson.M{"$lt": 10}
		}
	}
	if habitat != "" && habitat != "doesn't matter" {
		filter["habitat"] = habitat
	}
	if population != "" && population != "doesn't matter" {
		switch population {
		case "not sufficiently studied":
			filter["populationCount"] = bson.M{"$lt": 100}
		case "rare":
			filter["populationCount"] = bson.M{"$gte": 10000, "$lt": 50000}
		case "moderate":
			filter["populationCount"] = bson.M{"$gte": 50000, "$lt": 100000}
		case "abundant":
			filter["populationCount"] = bson.M{"$gte": 100000}
		}
	}

	// Выполнение запроса к базе данных
	collection := client.Database("example_db").Collection("whales")
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		http.Error(w, "Failed to fetch filtered whales", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		http.Error(w, "Failed to parse filtered whales", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

func sortWhalesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем параметры сортировки
	sortBy := r.URL.Query().Get("sortBy")
	order := r.URL.Query().Get("order")

	// Задаем порядок сортировки
	sortOrder := 1 // По умолчанию - по возрастанию
	if order == "desc" {
		sortOrder = -1
	}

	// Разрешенные поля для сортировки
	allowedSortFields := map[string]bool{
		"name":            true,
		"size":            true,
		"populationCount": true,
	}

	if !allowedSortFields[sortBy] {
		http.Error(w, "Invalid sort field", http.StatusBadRequest)
		return
	}

	// Формируем параметры сортировки
	sort := bson.D{{Key: sortBy, Value: sortOrder}}

	// Получаем отсортированные данные
	collection := client.Database("example_db").Collection("whales")
	options := options.Find().SetSort(sort)
	cursor, err := collection.Find(context.TODO(), bson.M{}, options)
	if err != nil {
		http.Error(w, "Failed to fetch sorted whales", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		http.Error(w, "Failed to parse sorted whales", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

func paginateWhalesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	// Получаем параметры сортировки и пагинации
	sortBy := r.URL.Query().Get("sortBy")
	order := r.URL.Query().Get("order")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

	// Парсим номера страниц и лимит
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}

	skip := (page - 1) * limit

	sortOrder := 1
	if order == "desc" {
		sortOrder = -1
	}

	sort := bson.D{}
	if sortBy != "" {
		sort = bson.D{{Key: sortBy, Value: sortOrder}}
	}

	// Получаем данные из MongoDB с пагинацией
	collection := client.Database("example_db").Collection("whales")
	options := options.Find().SetSort(sort).SetSkip(int64(skip)).SetLimit(int64(limit))

	cursor, err := collection.Find(context.TODO(), bson.M{}, options)
	if err != nil {
		http.Error(w, "Failed to fetch whales", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		http.Error(w, "Failed to parse whales", http.StatusInternalServerError)
		return
	}

	// Возвращаем результат
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

func main() {
	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalf("Error connecting to MongoDB: %v", err)
	}
	usersCollection = client.Database("auth_system").Collection("users")

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)

	http.HandleFunc("/api/whales/create", createWhaleHandler)
	http.HandleFunc("/api/whales/list", getWhalesHandler)
	http.HandleFunc("/api/whales/delete", deleteWhale)
	http.HandleFunc("/api/whales/update", updateWhale)
	http.HandleFunc("/api/whales/sort", sortWhalesHandler)
	http.HandleFunc("/api/whales/paginate", paginateWhalesHandler)

	http.HandleFunc("/api/register", register)
	http.HandleFunc("/api/confirm", confirmEmail)
	http.HandleFunc("/api/login", login)
	http.HandleFunc("/api/logout", logout)
	http.HandleFunc("/api/protected", protected)

	http.HandleFunc("/form", uploadHandler)

	http.HandleFunc("/api/whales/filter", filterWhalesHandler)

	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
