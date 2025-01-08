package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/smtp"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus" // <-- Structured logging
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate" // <-- Rate limiting
)

// ----------------------------------------------------------
// 1. Global variables
// ----------------------------------------------------------

// MongoDB client
var client *mongo.Client

// Create a global structured logger using logrus
var logger = logrus.New()

// Rate limiter: 2 requests per second with a burst of 5
var limiter = rate.NewLimiter(2, 5)

// Secret key for signing tokens (choose your own securely)
var jwtKey = []byte("your_secret_key")

// ----------------------------------------------------------
// 2. Models
// ----------------------------------------------------------

// Whale represents the whale model
type Whale struct {
	ID              primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Name            string             `json:"name"`
	DietType        string             `json:"dietType"`
	Size            float64            `json:"size"`
	Habitat         string             `json:"habitat"`
	PopulationCount int                `json:"populationCount"`
}

// User represents a user in the system
type User struct {
	ID           primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	Email        string             `json:"email"`
	Password     string             `json:"password"`
	Orders       []string           `json:"orders"`
	Interactions []string           `json:"interactions"`
}

// SupportMessage represents a support message sent by a user
type SupportMessage struct {
	UserID    primitive.ObjectID `json:"userId"`
	Subject   string             `json:"subject"`
	Message   string             `json:"message"`
	FilePaths []string           `json:"filePaths"`
}

// Claims structure for JWT
type Claims struct {
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// ----------------------------------------------------------
// 3. Connecting to MongoDB
// ----------------------------------------------------------

func connectToMongoDB() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		logger.WithError(err).Fatal("Failed to connect to MongoDB")
	}

	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		logger.WithError(err).Fatal("Could not ping MongoDB")
	}

	logger.WithFields(logrus.Fields{
		"action": "start",
		"status": "success",
	}).Info("Connected to MongoDB!")
}

// ----------------------------------------------------------
// 4. Logging user actions
// ----------------------------------------------------------

// LogAction writes a structured log for user actions, e.g., page visits, filters, etc.
func LogAction(action, detail, userID string) {
	logger.WithFields(logrus.Fields{
		"timestamp": time.Now().Format(time.RFC3339),
		"userID":    userID,
		"action":    action,
		"detail":    detail,
	}).Info("User action logged")
}

// wrapperHandler is a middleware that applies rate-limiting and logs requests.
func wrapperHandler(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// --- Rate limiting check ---
		if !limiter.Allow() {
			logger.Warn("Rate limit exceeded")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Log the incoming request path
		LogAction("Incoming Request", r.URL.Path, "UnknownUser")

		h.ServeHTTP(w, r)
	}
}

// ----------------------------------------------------------
// 5. Handlers (Users)
// ----------------------------------------------------------

// createUserHandler creates a new user and saves them to the database
func createUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		logger.WithError(err).Error("Invalid JSON data for user creation")
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Check for required fields
	if user.Email == "" || user.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.WithError(err).Error("Failed to hash password")
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Insert user into MongoDB
	collection := client.Database("example_db").Collection("users")
	_, err = collection.InsertOne(context.TODO(), user)
	if err != nil {
		logger.WithError(err).Error("Failed to create user in the database")
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	LogAction("User Created", fmt.Sprintf("Email: %s", user.Email), "System")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	var updates User
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		logger.WithError(err).Error("Invalid JSON data for user update")
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	collection := client.Database("example_db").Collection("users")
	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": objID}, bson.M{"$set": updates})
	if err != nil {
		logger.WithError(err).Error("Failed to update user in the database")
		http.Error(w, "Failed to update user", http.StatusInternalServerError)
		return
	}

	LogAction("User Updated", fmt.Sprintf("UserID: %s", id), id)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "User updated successfully"})
}

func getUserDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "User ID is required", http.StatusBadRequest)
		return
	}

	objID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		http.Error(w, "Invalid User ID", http.StatusBadRequest)
		return
	}

	collection := client.Database("example_db").Collection("users")
	var user User
	if err := collection.FindOne(context.TODO(), bson.M{"_id": objID}).Decode(&user); err != nil {
		logger.WithError(err).Warn("User not found in the database")
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	LogAction("Get User Data", fmt.Sprintf("UserID: %s", id), id)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// ----------------------------------------------------------
// 6. Handlers (Authentication)
// ----------------------------------------------------------

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials User
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		logger.WithError(err).Error("Invalid JSON data for login")
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Retrieve the user from the database
	collection := client.Database("example_db").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": credentials.Email}).Decode(&user)
	if err != nil {
		logger.WithError(err).Warn("Invalid email or password (user not found)")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Compare the provided password with the stored hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		logger.WithError(err).Warn("Invalid email or password (wrong password)")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Create a JWT token
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		logger.WithError(err).Error("Failed to generate JWT token")
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	LogAction("User Login", fmt.Sprintf("Email: %s", user.Email), user.ID.Hex())
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenStr = tokenStr[len("Bearer "):] // Remove "Bearer " prefix

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil || !token.Valid {
		logger.WithError(err).Warn("Invalid or expired token in profileHandler")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	LogAction("Profile Access", "User viewed profile", claims.Email)
	json.NewEncoder(w).Encode(map[string]string{"email": claims.Email})
}

// ----------------------------------------------------------
// 7. Handlers (Support)
// ----------------------------------------------------------

// (A) The simpler HTML-based email sender from the first code
//
//	If you want to keep this separate or unify with sendEmail, that’s up to you.
func sendMailSimpleHTML(subject, message string, to []string) error {
	headers := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";"
	msg := "Subject: " + subject + "\n" + headers + "\n\n" + message

	auth := smtp.PlainAuth(
		"",
		"your_gmail_address@gmail.com",
		"your_app_password", // e.g. 'cxnfodqgjvbwufsn'
		"smtp.gmail.com",
	)

	return smtp.SendMail(
		"smtp.gmail.com:587",
		auth,
		"your_gmail_address@gmail.com",
		to,
		[]byte(msg),
	)
}

// (B) The uploadHandler from the first code, for sending a form + optional image
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

		// Send email (to yourself or support)
		err = sendMailSimpleHTML(subject, message, []string{"your_gmail_address@gmail.com"})
		if err != nil {
			http.Error(w, "Failed to send email: "+err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintln(w, "Email sent successfully!")
		return
	}

	// Render form
	tmpl, err := template.ParseFiles("form") // Make sure "form" is in your ./static or root folder
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		logger.WithError(err).Error("Template parsing error in uploadHandler")
		return
	}
	tmpl.Execute(w, nil)
}

// (C) The more advanced "sendSupportMessageHandler" from the second code
//
//	that sends an email with multiple attachments
func sendSupportMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var message SupportMessage
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		logger.WithError(err).Error("Failed to parse multipart form data")
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	message.UserID, _ = primitive.ObjectIDFromHex(r.FormValue("userId"))
	message.Subject = r.FormValue("subject")
	message.Message = r.FormValue("message")

	files := r.MultipartForm.File["attachments"]
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			logger.WithError(err).Error("Failed to open attachment")
			http.Error(w, "Failed to open attachment", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		path := fmt.Sprintf("uploads/%s", fileHeader.Filename)
		out, err := os.Create(path)
		if err != nil {
			logger.WithError(err).Error("Failed to save attachment")
			http.Error(w, "Failed to save attachment", http.StatusInternalServerError)
			return
		}
		defer out.Close()

		if _, err := io.Copy(out, file); err != nil {
			logger.WithError(err).Error("Failed to copy attachment")
			http.Error(w, "Failed to copy attachment", http.StatusInternalServerError)
			return
		}
		message.FilePaths = append(message.FilePaths, path)
	}

	if err := sendEmail(message); err != nil {
		logger.WithError(err).Error("Failed to send support message (sendEmail)")
		http.Error(w, "Failed to send support message", http.StatusInternalServerError)
		return
	}

	LogAction("Support Request", message.Subject, message.UserID.Hex())
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Support message sent successfully"})
}

// sendEmail is a more generic function for sending mail (from the second code)
func sendEmail(message SupportMessage) error {
	// Customize with your credentials
	smtpHost := "smtp.example.com"
	smtpPort := "587"
	sender := "noreply@example.com"
	password := "yourpassword"
	recipient := "support@example.com"

	subject := fmt.Sprintf("Subject: %s\r\n", message.Subject)
	body := fmt.Sprintf("From: UserID: %s\n\n%s", message.UserID.Hex(), message.Message)

	var msg bytes.Buffer
	msg.WriteString(subject)
	msg.WriteString(body)

	auth := smtp.PlainAuth("", sender, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, sender, []string{recipient}, msg.Bytes())
}

// ----------------------------------------------------------
// 8. Handlers (Whales)
// ----------------------------------------------------------

func createWhaleHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var whale Whale
	if err := json.NewDecoder(r.Body).Decode(&whale); err != nil {
		logger.WithError(err).Error("Invalid JSON data for whale creation")
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
		logger.WithError(err).Error("Failed to create whale record in the database")
		http.Error(w, "Failed to create whale record", http.StatusInternalServerError)
		return
	}

	LogAction("Create Whale", whale.Name, "System")
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
		logger.WithError(err).Error("Failed to fetch whale records from the database")
		http.Error(w, "Failed to fetch whale records", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		logger.WithError(err).Error("Failed to parse whale records")
		http.Error(w, "Failed to parse whale records", http.StatusInternalServerError)
		return
	}

	// Example of an error scenario if empty:
	if len(whales) == 0 {
		logger.Warn("No whale records found")
		http.Error(w, "No whale records found", http.StatusNotFound)
		return
	}

	LogAction("Get Whales", "Retrieved all whales", "System")
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
	res, err := collection.DeleteOne(context.TODO(), bson.M{"_id": objID})
	if err != nil {
		logger.WithError(err).Error("Failed to delete whale from the database")
		http.Error(w, "Failed to delete whale", http.StatusInternalServerError)
		return
	}

	if res.DeletedCount == 0 {
		logger.Warn("No whale found to delete")
		http.Error(w, "No whale found to delete", http.StatusNotFound)
		return
	}

	LogAction("Delete Whale", fmt.Sprintf("WhaleID: %s", id), "System")
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
		logger.WithError(err).Error("Invalid JSON data for whale update")
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
		logger.WithError(err).Error("Failed to update whale in the database")
		http.Error(w, "Failed to update whale", http.StatusInternalServerError)
		return
	}

	LogAction("Update Whale", fmt.Sprintf("WhaleID: %s", id), "System")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Whale updated successfully"})
}

func filterWhalesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	dietType := r.URL.Query().Get("dietType")
	size := r.URL.Query().Get("size")
	habitat := r.URL.Query().Get("habitat")
	population := r.URL.Query().Get("population")

	filter := bson.M{}
	if dietType != "" && dietType != "doesn't matter" {
		filter["dietType"] = dietType
	}
	if size != "" && size != "doesn't matter" {
		switch size {
		case "large":
			filter["size"] = bson.M{"$gte": 20}
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

	collection := client.Database("example_db").Collection("whales")
	cursor, err := collection.Find(context.TODO(), filter)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch filtered whales from the database")
		http.Error(w, "Failed to fetch filtered whales", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		logger.WithError(err).Error("Failed to parse filtered whales")
		http.Error(w, "Failed to parse filtered whales", http.StatusInternalServerError)
		return
	}

	if len(whales) == 0 {
		logger.Warn("No products match the filter")
		http.Error(w, "No products match the filter", http.StatusNotFound)
		return
	}

	LogAction("Filter Whales", "Applied filter", "System")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

func sortWhalesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	sortBy := r.URL.Query().Get("sortBy")
	order := r.URL.Query().Get("order")

	sortOrder := 1
	if order == "desc" {
		sortOrder = -1
	}

	allowedSortFields := map[string]bool{
		"name":            true,
		"size":            true,
		"populationCount": true,
	}

	if sortBy == "" {
		sortBy = "name"
	}
	if !allowedSortFields[sortBy] {
		logger.Warn("Invalid sort field")
		http.Error(w, "Invalid sort field", http.StatusBadRequest)
		return
	}

	sort := bson.D{{Key: sortBy, Value: sortOrder}}

	collection := client.Database("example_db").Collection("whales")
	opts := options.Find().SetSort(sort)
	cursor, err := collection.Find(context.TODO(), bson.M{}, opts)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch sorted whales from the database")
		http.Error(w, "Failed to fetch sorted whales", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		logger.WithError(err).Error("Failed to parse sorted whales")
		http.Error(w, "Failed to parse sorted whales", http.StatusInternalServerError)
		return
	}

	if len(whales) == 0 {
		logger.Warn("No whale records found for sorting")
		http.Error(w, "No whale records found", http.StatusNotFound)
		return
	}

	LogAction("Sort Whales", fmt.Sprintf("Sorting by: %s, order: %s", sortBy, order), "System")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

func paginateWhalesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	sortBy := r.URL.Query().Get("sortBy")
	order := r.URL.Query().Get("order")
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")

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

	collection := client.Database("example_db").Collection("whales")
	opts := options.Find().SetSort(sort).SetSkip(int64(skip)).SetLimit(int64(limit))

	cursor, err := collection.Find(context.TODO(), bson.M{}, opts)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch whales for pagination from the database")
		http.Error(w, "Failed to fetch whales", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []Whale
	if err = cursor.All(context.TODO(), &whales); err != nil {
		logger.WithError(err).Error("Failed to parse whales (pagination)")
		http.Error(w, "Failed to parse whales", http.StatusInternalServerError)
		return
	}

	if len(whales) == 0 {
		logger.Warn("No whales found in pagination query")
		http.Error(w, "No whales found", http.StatusNotFound)
		return
	}

	LogAction("Paginate Whales", fmt.Sprintf("Page: %d, Limit: %d", page, limit), "System")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

// ----------------------------------------------------------
// 9. Main function with Graceful Shutdown
// ----------------------------------------------------------

func main() {
	// 1. Configure logrus for JSON output (structured logging)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(os.Stdout) // You can also set this to a file
	logger.SetLevel(logrus.InfoLevel)

	// 2. Connect to MongoDB
	connectToMongoDB()

	// 3. Create an HTTP server (using a custom mux)
	mux := http.NewServeMux()

	// Serve static files
	mux.Handle("/", http.FileServer(http.Dir("./static")))

	// Whale routes
	mux.HandleFunc("/api/whales/create", wrapperHandler(createWhaleHandler))
	mux.HandleFunc("/api/whales/list", wrapperHandler(getWhalesHandler))
	mux.HandleFunc("/api/whales/delete", wrapperHandler(deleteWhale))
	mux.HandleFunc("/api/whales/update", wrapperHandler(updateWhale))
	mux.HandleFunc("/api/whales/sort", wrapperHandler(sortWhalesHandler))
	mux.HandleFunc("/api/whales/paginate", wrapperHandler(paginateWhalesHandler))
	mux.HandleFunc("/api/whales/filter", wrapperHandler(filterWhalesHandler))

	// User routes
	mux.HandleFunc("/createUser", wrapperHandler(createUserHandler))
	mux.HandleFunc("/api/users/update", wrapperHandler(updateUserHandler))
	mux.HandleFunc("/api/users/data", wrapperHandler(getUserDataHandler))

	// Auth routes
	mux.HandleFunc("/login", wrapperHandler(loginHandler))
	mux.HandleFunc("/profile", wrapperHandler(profileHandler))

	// Support routes
	mux.HandleFunc("/api/support/send", wrapperHandler(sendSupportMessageHandler))

	// The form endpoint from the first code
	mux.HandleFunc("/form", wrapperHandler(uploadHandler))

	// 4. Create the server struct
	srv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// 5. Graceful shutdown setup
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Run the server in a goroutine
	go func() {
		logger.WithFields(logrus.Fields{
			"action": "start_server",
			"status": "running",
		}).Info("Server is running on http://localhost:8080")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatalf("ListenAndServe(): %v", err)
		}
	}()

	// Block until we receive a signal
	<-quit
	logger.Info("Server is shutting down...")

	// Create a context with a 30-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatalf("Server forced to shutdown: %v", err)
	}

	logger.Info("Server exiting gracefully")
}
