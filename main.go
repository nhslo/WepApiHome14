package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Item struct {
	ID        int       `json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	OwnerID   int       `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}
type Claims struct {
	UserID int    `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}
type contextKey string

const userKey contextKey = "user"

var database *sql.DB
var secret []byte

func send(responseWriter http.ResponseWriter, status int, value any) {
	responseWriter.Header().Set("Content-Type", "application/json")
	responseWriter.WriteHeader(status)
	json.NewEncoder(responseWriter).Encode(value)
}

func fail(responseWriter http.ResponseWriter, operationError error) {
	log.Println(operationError)
	http.Error(responseWriter, "Server error", 500)
}

func readCredentials(request *http.Request) (Credentials, error) {
	var credentials Credentials
	operationError := json.NewDecoder(request.Body).Decode(&credentials)
	credentials.Username = strings.TrimSpace(credentials.Username)
	if operationError != nil || len(credentials.Username) < 3 || len(credentials.Username) > 100 || len(credentials.Password) < 8 || len([]byte(credentials.Password)) > 72 {
		return credentials, errors.New("invalid credentials")
	}
	return credentials, nil
}

// Сохраняем нового пользователя с хешем пароля и ролью user.
func register(responseWriter http.ResponseWriter, request *http.Request) {
	credentials, operationError := readCredentials(request)
	if operationError != nil {
		http.Error(responseWriter, "Invalid username or password", 400)
		return
	}
	if credentials.Role != "" {
		http.Error(responseWriter, "Role cannot be set during registration", 400)
		return
	}
	hash, operationError := bcrypt.GenerateFromPassword([]byte(credentials.Password), bcrypt.DefaultCost)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	var id int
	operationError = database.QueryRow("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'user') RETURNING id", credentials.Username, string(hash)).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(operationError, &pgErr) && pgErr.Code == "23505" {
		http.Error(responseWriter, "Username already exists", 409)
		return
	}
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	send(responseWriter, 201, map[string]any{"id": id, "username": credentials.Username, "role": "user"})
}

func login(responseWriter http.ResponseWriter, request *http.Request) {
	credentials, operationError := readCredentials(request)
	if operationError != nil {
		http.Error(responseWriter, "Invalid credentials", 401)
		return
	}
	var id int
	var hash, role string
	operationError = database.QueryRow("SELECT id,password_hash,role FROM users WHERE username=$1", credentials.Username).Scan(&id, &hash, &role)
	if errors.Is(operationError, sql.ErrNoRows) {
		http.Error(responseWriter, "Invalid credentials", 401)
		return
	}
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(credentials.Password)) != nil {
		http.Error(responseWriter, "Invalid credentials", 401)
		return
	}
	claims := Claims{UserID: id, Role: role, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
	token, operationError := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	send(responseWriter, 200, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": 3600})
}

// Проверяем токен и передаём ID и роль пользователя обработчику.
func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, request *http.Request) {
		parts := strings.Fields(request.Header.Get("Authorization"))
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(responseWriter, "Unauthorized", 401)
			return
		}
		claims := &Claims{}
		token, operationError := jwt.ParseWithClaims(parts[1], claims, func(receivedToken *jwt.Token) (any, error) { return secret, nil }, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
		if operationError != nil || !token.Valid || claims.UserID <= 0 || (claims.Role != "user" && claims.Role != "admin") {
			http.Error(responseWriter, "Unauthorized", 401)
			return
		}
		next(responseWriter, request.WithContext(context.WithValue(request.Context(), userKey, claims)))
	}
}

func scan(row interface{ Scan(...any) error }) (Item, error) {
	var item Item
	operationError := row.Scan(&item.ID, &item.Title, &item.Content, &item.OwnerID, &item.CreatedAt)
	return item, operationError
}

func getItem(id int) (Item, error) {
	return scan(database.QueryRow("SELECT id,title,content,owner_id,created_at FROM documents WHERE id=$1", id))
}

func idFrom(responseWriter http.ResponseWriter, request *http.Request) (int, bool) {
	id, operationError := strconv.Atoi(request.PathValue("id"))
	if operationError != nil || id <= 0 {
		http.Error(responseWriter, "Invalid ID", 400)
		return 0, false
	}
	return id, true
}

func list(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	rows, operationError := database.Query("SELECT id,title,content,owner_id,created_at FROM documents WHERE ($1 = 'admin' OR owner_id=$2) ORDER BY id", user.Role, user.UserID)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	defer rows.Close()
	items := []Item{}
	for rows.Next() {
		item, operationError := scan(rows)
		if operationError != nil {
			fail(responseWriter, operationError)
			return
		}
		items = append(items, item)
	}
	if operationError = rows.Err(); operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	send(responseWriter, 200, items)
}

func get(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	id, success := idFrom(responseWriter, request)
	if !success {
		return
	}
	item, operationError := getItem(id)
	if errors.Is(operationError, sql.ErrNoRows) {
		http.NotFound(responseWriter, request)
		return
	}
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	if item.OwnerID != user.UserID && user.Role != "admin" {
		http.Error(responseWriter, "Forbidden", 403)
		return
	}
	send(responseWriter, 200, item)
}

func valid(item Item) bool {
	return strings.TrimSpace(item.Title) != "" && strings.TrimSpace(item.Content) != ""
}

func create(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	var item Item
	if json.NewDecoder(request.Body).Decode(&item) != nil || !valid(item) {
		http.Error(responseWriter, "Invalid input", 400)
		return
	}
	item.OwnerID = user.UserID
	operationError := database.QueryRow("INSERT INTO documents(title,content,owner_id) VALUES($1,$2,$3) RETURNING id", item.Title, item.Content, item.OwnerID).Scan(&item.ID)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	item, operationError = getItem(item.ID)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	send(responseWriter, 201, item)
}

func update(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	id, success := idFrom(responseWriter, request)
	if !success {
		return
	}
	var item Item
	decodeErr := json.NewDecoder(request.Body).Decode(&item)
	current, operationError := getItem(id)
	if errors.Is(operationError, sql.ErrNoRows) {
		http.NotFound(responseWriter, request)
		return
	}
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	if current.OwnerID != user.UserID {
		http.Error(responseWriter, "Forbidden", 403)
		return
	}
	if decodeErr != nil || !valid(item) {
		http.Error(responseWriter, "Invalid input", 400)
		return
	}
	_, operationError = database.Exec("UPDATE documents SET title=$1,content=$2 WHERE id=$3", item.Title, item.Content, id)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	item, operationError = getItem(id)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	send(responseWriter, 200, item)
}

func remove(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	id, success := idFrom(responseWriter, request)
	if !success {
		return
	}
	current, operationError := getItem(id)
	if errors.Is(operationError, sql.ErrNoRows) {
		http.NotFound(responseWriter, request)
		return
	}
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	if current.OwnerID != user.UserID && user.Role != "admin" {
		http.Error(responseWriter, "Forbidden", 403)
		return
	}
	_, operationError = database.Exec("DELETE FROM documents WHERE id=$1", id)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	responseWriter.WriteHeader(204)
}

func stats(responseWriter http.ResponseWriter, request *http.Request) {
	user := request.Context().Value(userKey).(*Claims)
	if user.Role != "admin" {
		http.Error(responseWriter, "Forbidden", 403)
		return
	}
	var users, items int
	operationError := database.QueryRow("SELECT (SELECT COUNT(*) FROM users),(SELECT COUNT(*) FROM documents)").Scan(&users, &items)
	if operationError != nil {
		fail(responseWriter, operationError)
		return
	}
	send(responseWriter, 200, map[string]int{"users": users, "documents": items})
}

func createAdmin() {
	username := strings.TrimSpace(os.Getenv("ADMIN_USERNAME"))
	password := os.Getenv("ADMIN_PASSWORD")
	if len(username) < 3 || len(password) < 8 || len([]byte(password)) > 72 {
		log.Fatal("Set ADMIN_USERNAME and ADMIN_PASSWORD")
	}
	hash, operationError := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if operationError != nil {
		log.Fatal(operationError)
	}
	_, operationError = database.Exec("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'admin')", username, string(hash))
	if operationError != nil {
		log.Fatal(operationError)
	}
	fmt.Println("Administrator created")
}

func main() {
	connectionString := os.Getenv("DATABASE_URL")
	secret = []byte(os.Getenv("JWT_SECRET"))
	if connectionString == "" || len(secret) == 0 {
		log.Fatal("Set DATABASE_URL and JWT_SECRET")
	}
	var operationError error
	database, operationError = sql.Open("pgx", connectionString)
	if operationError != nil {
		log.Fatal(operationError)
	}
	defer database.Close()
	if operationError = database.Ping(); operationError != nil {
		log.Fatal(operationError)
	}
	if len(os.Args) > 1 && os.Args[1] == "create-admin" {
		createAdmin()
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", register)
	mux.HandleFunc("POST /auth/login", login)
	mux.HandleFunc("GET /documents", auth(list))
	mux.HandleFunc("GET /documents/{id}", auth(get))
	mux.HandleFunc("POST /documents", auth(create))
	mux.HandleFunc("PUT /documents/{id}", auth(update))
	mux.HandleFunc("DELETE /documents/{id}", auth(remove))
	mux.HandleFunc("GET /admin/statistics", auth(stats))
	log.Println("http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
