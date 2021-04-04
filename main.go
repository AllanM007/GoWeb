package main

import (
    "fmt"
    "log"
    "time"
    "net/http"
    "io/ioutil"
    //"encoding/json"
    //"/basic-middleware"
    "database/sql"
    "html/template"
    "golang.org/x/crypto/bcrypt"
    "github.com/gorilla/sessions"
    "github.com/gorilla/websocket"
    _ "github.com/go-sql-driver/mysql"
)

type Todo struct {
    Title string
    Done  bool
}


type TodoPageData struct {
    PageTitle string
    Todos     []Todo
}

type SecretData struct {
    PageTitle string
    Secret string
}

type ContactDetails struct {
    Email   string
    Subject string
    Message string
}

var (
    // key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
    key = []byte("super-secret-key")
    store = sessions.NewCookieStore(key)
)

var upgrader = websocket.Upgrader{
    ReadBufferSize:  1024,
    WriteBufferSize: 1024,
}

func login(w http.ResponseWriter, r* http.Request) {
    session, _ := store.Get(r, "cookie-name")

    session.Values["authenticated"] = true
    session.Save(r, w)

    fmt.Println("Endpoint Hit: Login")
    fmt.Fprintf(w, "%v", session)
}

func logout(w http.ResponseWriter, r* http.Request) {
    session, _ := store.Get(r, "cookie-name")

    session.Values["authenticated"] = false
    session.Save(r, w)

    fmt.Println("Endpoint Hit: Logout")
    fmt.Fprintf(w, "%v", session)
}

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func showPass(w http.ResponseWriter, r* http.Request) {
    password := "secret"

    hashPass, _ := HashPassword(password)

    fmt.Fprintf(w, "Password : %v", password)
    fmt.Fprintf(w, "Hash : %v", hashPass)

    match := CheckPasswordHash(password, hashPass)
    fmt.Fprintf(w, "Match : %v", match)
}

func webSocket(w http.ResponseWriter, r* http.Request) {
    conn, _ := upgrader.Upgrade(w, r, nil)

    for {
        // Read message from browser
        msgType, msg, err := conn.ReadMessage()
        if err != nil {
            return
        }

        // Print the message to the console
        fmt.Printf("%s sent: %s\n", conn.RemoteAddr(), string(msg))

        // Write message back to browser
        if err = conn.WriteMessage(msgType, msg); err != nil {
            return
        }
    }
}

func homeChat(w http.ResponseWriter, r* http.Request) {

    tmpl := template.Must(template.ParseFiles("templates/websockets.html"))

    data := SecretData{
        PageTitle: "WebSocket Chat",
    }
    tmpl.Execute(w, data)
}

func dbPing(w http.ResponseWriter, r* http.Request) {
	
	// Configure the database connection (always check errors)
	db, err := sql.Open("mysql", "root:MysqlPassword1#@(127.0.0.1:3306)/gowebdb?parseTime=true")
	defer db.Close()
	// Initialize the first connection to the database, to see if everything works correctly.
	// Make sure to check the error.
	err = db.Ping()

	if err != nil {
		log.Fatalln(err)
	}

	username := "johndoe"
	password := "secret"
	createdAt := time.Now()

	// Inserts our data into the users table and returns with the result and a possible error.
	// The result contains information about the last inserted id (which was auto-generated for us) and the count of rows this query affected.
	result, err2 := db.Exec(`INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)`, username, password, createdAt)
	//defer result.Close()

	if err2 != nil {
		log.Fatal(err2) 
	}
	userID, err2 := result.LastInsertId()

	fmt.Fprintf(w, "%v", userID)

}

func queryDb(w http.ResponseWriter, req *http.Request) {
	var (
		id        int
		username  string
		password  string
		createdAt time.Time
	)

	db, err := sql.Open("mysql", "root:MysqlPassword1#@(127.0.0.1:3306)/gowebdb?parseTime=true")

	// Query the database and scan the values into out variables. Don't forget to check for errors.
	query := `SELECT id, username, password, created_at FROM users WHERE id = ?`
	result2 := db.QueryRow(query, 1).Scan(&id, &username, &password, &createdAt)

	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	fmt.Println(w, "%v", result2)

	{ // Query a single user
        var (
            id        int
            username  string
            password  string
            createdAt time.Time
        )

        query := "SELECT id, username, password, created_at FROM users WHERE id = ?"
        if err := db.QueryRow(query, 1).Scan(&id, &username, &password, &createdAt); err != nil {
            log.Fatal(err)
        }

        fmt.Println(id, username, password, createdAt)
    }

    { // Query all users
        type user struct {
            id        int
            username  string
            password  string
            createdAt time.Time
        }

        rows, err := db.Query(`SELECT id, username, password, created_at FROM users`)
        if err != nil {
            log.Fatal(err)
        }
        defer rows.Close()

        var users []user
        for rows.Next() {
            var u user

            err := rows.Scan(&u.id, &u.username, &u.password, &u.createdAt)
            if err != nil {
                log.Fatal(err)
            }
            users = append(users, u)
        }
        if err := rows.Err(); err != nil {
            log.Fatal(err)
        }

        fmt.Printf("%#v", users)
    }

    {
        _, err := db.Exec(`DELETE FROM users WHERE id = ?`, 1)
        if err != nil {
            log.Fatal(err)
        }
    }
}

func getPage(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/layout.html"))

	data := TodoPageData{
		PageTitle: "My TODO list",
		Todos: []Todo{
			{Title: "Task 1", Done: false},
			{Title: "Task 2", Done: true},
			{Title: "Task 3", Done: true},
		},
	}
	tmpl.Execute(w, data)
}

func secretPage(w http.ResponseWriter, r* http.Request) {

    session, _ := store.Get(r, "cookie-name")

    // Check if user is authenticated
    if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }

    tmpl := template.Must(template.ParseFiles("templates/secret.html"))

    data := SecretData{
        PageTitle: "Secret Page",
        Secret : "I love Golang!!",
    }
    tmpl.Execute(w, data)
}

func contactForm(w http.ResponseWriter, r *http.Request) {

	db, err := sql.Open("mysql", "root:MysqlPassword1#@(127.0.0.1:3306)/gowebdb?parseTime=true")
	defer db.Close()

	if err != nil {
		log.Fatal(err)
	}

	tmpl := template.Must(template.ParseFiles("templates/form.html"))

	if r.Method != http.MethodPost {
		tmpl.Execute(w, nil)
		return
	}

	details := ContactDetails{
		Email:   r.FormValue("email"),
		Subject: r.FormValue("subject"),
		Message: r.FormValue("message"),
	}

	result, err2 := db.Exec(`INSERT INTO contactform (email, subject, message) VALUES (?, ?, ?)`, r.FormValue("email"), r.FormValue("subject"), r.FormValue("message"))

	if err2 != nil {
		log.Fatal(err2) 
	}

	// do something with details
	_ = details

	fmt.Println(result)

	tmpl.Execute(w, struct{ Success bool }{true})
}

func hello(w http.ResponseWriter, req *http.Request) {

    fmt.Fprintf(w, "hello\n")
}

func headers(w http.ResponseWriter, req *http.Request) {

    for name, headers := range req.Header {
        for _, h := range headers {
            fmt.Fprintf(w, "%v: %v\n", name, h)
        }
    }
}

func gettest(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "Get is Working\n")
}

func serveStatic(w http.ResponseWriter, req *http.Request) {

	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/css/", http.StripPrefix("/css/", fs))

	log.Printf("Endpoint Hit: serveStatic")
}


const (
    USERNAME = "mzawadi"
    PASSWORD = "IkigaiMzawadi2021#"
    URL      = "https://ikigaicredits.mzawadi.com/api/v1/users"
)

func getjson(w http.ResponseWriter, req *http.Request) {

	req, err := http.NewRequest("GET", URL, nil)
    req.SetBasicAuth(USERNAME, PASSWORD)

    req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}

	resp, err := client.Do(req)

	if err != nil {
		log.Fatalln(err)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	
	//Convert the body to type string
	sb := string(body)
	//log.Printf(sb)

	log.Printf("Endpoint Hit: getJson")

	fmt.Fprintf(w, "%v", sb)
}

func Logging(f http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        log.Println(r.URL.Path)
        f(w, r)
    }
}

func foo(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "foo")
}

func bar(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "bar")
}

func main() {

    http.HandleFunc("/hello", hello)
    http.HandleFunc("/login", login)
    http.HandleFunc("/logout", logout)
    http.HandleFunc("/chat", homeChat)
    http.HandleFunc("/echo", webSocket)
    http.HandleFunc("/password", showPass)
    http.HandleFunc("/headers", headers)
    http.HandleFunc("/gettest", gettest)
    http.HandleFunc("/getjson", getjson)
    http.HandleFunc("/serve", serveStatic)
    http.HandleFunc("/dbping", dbPing)
    http.HandleFunc("/secret", secretPage)
    http.HandleFunc("/querydb", queryDb)
    http.HandleFunc("/getpage", getPage)
    http.HandleFunc("/form", contactForm)
    http.HandleFunc("/foo", Logging(foo))
    http.HandleFunc("/bar", Logging(bar))

    http.ListenAndServe(":8090", nil)
}