package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client

func connectToMongo() {
	uri := "mongodb://localhost:27017"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	client, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Could not ping MongoDB:", err)
	}

	fmt.Println("Connected to MongoDB!")
}

func addWhale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is supported", http.StatusMethodNotAllowed)
		return
	}

	type Whale struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	var whale Whale
	err := json.NewDecoder(r.Body).Decode(&whale)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	collection := client.Database("whale_project").Collection("whales")
	_, err = collection.InsertOne(context.TODO(), whale)
	if err != nil {
		http.Error(w, "Failed to save data to database", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Whale added successfully!"))
}

func getWhaleByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is supported", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID parameter is required", http.StatusBadRequest)
		return
	}

	collection := client.Database("whale_project").Collection("whales")
	var whale bson.M
	err := collection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&whale)
	if err != nil {
		http.Error(w, "Whale not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whale)
}

func updateWhale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is supported", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID parameter is required", http.StatusBadRequest)
		return
	}

	var updateData bson.M
	err := json.NewDecoder(r.Body).Decode(&updateData)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	collection := client.Database("whale_project").Collection("whales")
	result, err := collection.UpdateOne(context.TODO(), bson.M{"_id": id}, bson.M{
		"$set": updateData,
	})
	if err != nil || result.MatchedCount == 0 {
		http.Error(w, "Failed to update whale", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Whale updated successfully!"))
}

func deleteWhale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE method is supported", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID parameter is required", http.StatusBadRequest)
		return
	}

	collection := client.Database("whale_project").Collection("whales")
	result, err := collection.DeleteOne(context.TODO(), bson.M{"_id": id})
	if err != nil || result.DeletedCount == 0 {
		http.Error(w, "Failed to delete whale", http.StatusInternalServerError)
		return
	}

	w.Write([]byte("Whale deleted successfully!"))
}

func getWhales(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is supported", http.StatusMethodNotAllowed)
		return
	}

	collection := client.Database("whale_project").Collection("whales")
	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		http.Error(w, "Failed to fetch whales", http.StatusInternalServerError)
		return
	}
	defer cursor.Close(context.TODO())

	var whales []bson.M
	if err = cursor.All(context.TODO(), &whales); err != nil {
		http.Error(w, "Failed to parse whales", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(whales)
}

func seedDatabase() {
	collection := client.Database("whale_project").Collection("whales")
	whales := []interface{}{
		bson.M{"name": "Blue Whale", "description": "The largest animal on Earth"},
		bson.M{"name": "Humpback Whale", "description": "Known for its magical songs"},
	}
	_, err := collection.InsertMany(context.TODO(), whales)
	if err != nil {
		log.Fatal("Failed to seed database:", err)
	}
	fmt.Println("Database seeded successfully!")
}

func enableCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	connectToMongo()

	// Uncomment to seed database
	// seedDatabase()

	mux := http.NewServeMux()
	mux.Handle("/add-whale", enableCors(http.HandlerFunc(addWhale)))
	mux.Handle("/get-whale", enableCors(http.HandlerFunc(getWhaleByID)))
	mux.Handle("/update-whale", enableCors(http.HandlerFunc(updateWhale)))
	mux.Handle("/delete-whale", enableCors(http.HandlerFunc(deleteWhale)))
	mux.Handle("/get-whales", enableCors(http.HandlerFunc(getWhales)))

	fmt.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
