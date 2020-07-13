package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/buaazp/fasthttprouter"
	"github.com/valyala/fasthttp"
	"github.com/xellio/whois"

	"regexp"

	_ "github.com/lib/pq"
)

type SSLEndpointResponse struct {
	IPAddress string `json:"ipAddress"`
	Grade     string `json:"grade"`
}

type SSLResponse struct {
	Status    string                `json:"status"`
	Host      string                `json:"host"`
	Port      string                `json:"port"`
	Endpoints []SSLEndpointResponse `json:"endpoints"`
}

type Server struct {
	Address  string `json:"address"`
	SSLGrade string `json:"ssl_grade"`
	Country  string `json:"country"`
	Owner    string `json:"owner"`
}

type Domain struct {
	Address          string   `json:"address"`
	IsDown           bool     `json:"is_down"`
	Logo             string   `json:"logo"`
	PreviousSSLGrade string   `json:"previous_ssl_grade"`
	Servers          []Server `json:"servers"`
	ServersChanged   bool     `json:"servers_changed"`
	SSLGrade         string   `json:"ssl_grade"`
	Title            string   `json:"title"`
}

type Connection struct {
	Domain     Domain    `json:"domain"`
	LastUpdate time.Time `json:"last_update"`
}

type Item struct {
	Connections []Connection `json:"items"`
}

// var IP = "carlos@35.170.250.98:26257"
var IP = "carlos@localhost:26257"

func IndexRoute(ctx *fasthttp.RequestCtx) {
	fmt.Fprint(ctx, "Welcome to go backend!\n")
}

func ConnectionRoute(ctx *fasthttp.RequestCtx) {
	response, err := getConnectionInfo(ctx)

	ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	if err != nil {
		fmt.Println("Error in ConnectionRoute :", err)
		ctx.Response.SetStatusCode(500)

	} else {
		var (
			strContentType     = []byte("Content-Type")
			strApplicationJSON = []byte("application/json")
		)

		ctx.Response.Header.SetCanonical(strContentType, strApplicationJSON)
		ctx.Response.SetStatusCode(200)
		json.NewEncoder(ctx).Encode(response)

	}

}

func ConnectionFilterRoute(ctx *fasthttp.RequestCtx) {
	response, err := getConnectionFilterInfo(ctx)

	ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	if err != nil {
		fmt.Println("Error in ConnectionRoute :", err)
		ctx.Response.SetStatusCode(500)

	} else {
		var (
			strContentType     = []byte("Content-Type")
			strApplicationJSON = []byte("application/json")
		)

		ctx.Response.Header.SetCanonical(strContentType, strApplicationJSON)
		ctx.Response.SetStatusCode(200)
		json.NewEncoder(ctx).Encode(response)

	}

}

func DomainRoute(ctx *fasthttp.RequestCtx) {
	response, err := getDomainInfo(ctx)

	ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	if err != nil {
		fmt.Println("Error in DomainRoute :", err)
		ctx.Response.SetStatusCode(500)

	} else {
		var (
			strContentType     = []byte("Content-Type")
			strApplicationJSON = []byte("application/json")
		)

		ctx.Response.Header.SetCanonical(strContentType, strApplicationJSON)
		ctx.Response.SetStatusCode(200)
		json.NewEncoder(ctx).Encode(response)

	}

}

func getConnectionInfo(ctx *fasthttp.RequestCtx) (Item, error) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")

	var itemResponse Item
	var connections []Connection

	host := ctx.RemoteIP().String()

	rows, err := db.Query("SELECT DomainAddress, DB.Connection.LastUpdate, IsDown, Logo, SSLGrade, Title FROM DB.Domain, DB.Connection WHERE OriginIP = $1  and DomainAddress = Address", host)
	if err != nil {
		fmt.Println("error", err)
	}
	defer rows.Close()
	for rows.Next() {
		var lastUpdate time.Time

		var domainAddress string
		var isDown bool
		var logo string
		var sslGrade string
		var title string

		if err := rows.Scan(&domainAddress, &lastUpdate, &isDown, &logo, &sslGrade, &title); err != nil {
			fmt.Println("error", err)
		}
		domain := Domain{Address: domainAddress, IsDown: isDown, Logo: logo, SSLGrade: sslGrade, Title: title}
		connection := Connection{LastUpdate: lastUpdate, Domain: domain}
		connections = append(connections, connection)
	}

	itemResponse = Item{Connections: connections}

	defer db.Close()
	return itemResponse, err
}

func getConnectionFilterInfo(ctx *fasthttp.RequestCtx) (Item, error) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")

	var itemResponse Item
	var connections []Connection

	host := ctx.RemoteIP().String()
	domain := ctx.UserValue("domain").(string)

	rows, err := db.Query("SELECT DomainAddress, DB.Connection.LastUpdate, IsDown, Logo, SSLGrade, Title FROM DB.Domain, DB.Connection WHERE OriginIP = $1 and DomainAddress = $2 and DomainAddress = Address", host, domain)
	if err != nil {
		fmt.Println("error", err)
	}
	defer rows.Close()
	for rows.Next() {
		var lastUpdate time.Time

		var domainAddress string
		var isDown bool
		var logo string
		var sslGrade string
		var title string

		if err := rows.Scan(&domainAddress, &lastUpdate, &isDown, &logo, &sslGrade, &title); err != nil {
			fmt.Println("error", err)
		}
		domain := Domain{Address: domainAddress, IsDown: isDown, Logo: logo, SSLGrade: sslGrade, Title: title}
		connection := Connection{LastUpdate: lastUpdate, Domain: domain}
		connections = append(connections, connection)
	}

	itemResponse = Item{Connections: connections}

	defer db.Close()
	return itemResponse, err
}

func getDomainInfo(ctx *fasthttp.RequestCtx) (Domain, error) {
	var domainResponse Domain

	host := ctx.RemoteIP().String()

	domain := ctx.UserValue("domain").(string)
	domainResult, err := whois.QueryHost(domain)
	if len(domainResult.Output["Domain Name"]) == 0 || err != nil {
		fmt.Println("Error in whois lookup :", err)
	} else {
		domainAddress := domainResult.Output["Domain Name"][0]
		domainServers, err := getServers(domain)
		if err != nil {
			fmt.Println("error getting servers ", err)
		}

		domainTitle, domainLogo, err := getTitleLogo(domain)
		if err != nil {
			fmt.Println("error getting title and logo ", err)
		}

		var domainIsDown bool
		if domainResult.Output["status"][0] == "ACTIVE" {
			domainIsDown = false
		} else {
			domainIsDown = true
		}

		domainResponse = Domain{Address: domainAddress, IsDown: domainIsDown, Logo: domainLogo,
			Servers: domainServers, Title: domainTitle}

		exists, err := existsDomainDB(domainAddress)

		if err != nil {
			fmt.Println("error querying domain in DB", err)
		}
		if exists == true {
			updateDomainServersDB(&domainResponse)
		} else if exists == false {
			insertDomainServersDB(&domainResponse)
		}

		existsOrigin, errOrigin := existsOriginDB(host)
		if errOrigin != nil {
			fmt.Println("error querying origin in DB", errOrigin)
		}
		insertConnectionDB(existsOrigin, host, "Some metadata", domainAddress)

	}

	return domainResponse, err
}

func existsDomainDB(domainAddress string) (bool, error) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")
	var address string

	if err != nil {
		fmt.Println("error connecting to DB", err)
		return true, err
	}

	row := db.QueryRow("SELECT Address FROM DB.Domain WHERE Address = $1", domainAddress)
	defer db.Close()

	switch err := row.Scan(&address); err {
	case sql.ErrNoRows:
		return false, nil
	case nil:
		return true, nil
	default:
		return true, err
	}
}

func existsOriginDB(hostAddress string) (bool, error) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")
	var Address string

	if err != nil {
		fmt.Println("error connecting to DB", err)
		return false, err
	}

	row := db.QueryRow("SELECT Address FROM DB.Origin WHERE Address = $1", hostAddress)
	defer db.Close()

	switch err := row.Scan(&Address); err {
	case sql.ErrNoRows:
		return false, nil
	case nil:
		return true, nil
	default:
		return false, err
	}

}

func existsServerDB(address string) (bool, error) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")
	var Address string

	if err != nil {
		fmt.Println("error connecting to DB", err)
		return false, err
	}

	row := db.QueryRow("SELECT Address FROM DB.Server WHERE Address = $1", address)
	defer db.Close()

	switch err := row.Scan(&Address); err {
	case sql.ErrNoRows:
		return false, nil
	case nil:
		return true, nil
	default:
		return false, err
	}

}

// get title and logo from specific domain
func getTitleLogo(domain string) (string, string, error) {
	url := "http://" + domain
	statusCode, body, err := fasthttp.Get(nil, url)

	if err != nil {
		fmt.Println("error in TitleLogo", statusCode, err)
		return "", "", err
	}

	formatedBody := string(body)

	var title string
	titleRegex := regexp.MustCompile(`<title.*?>(.*)</title>`)
	submatchalltitle := titleRegex.FindAllStringSubmatch(formatedBody, -1)
	if len(submatchalltitle) > 0 && len(submatchalltitle[0]) > 1 {
		title = utf8Decode(submatchalltitle[0][1])
	}

	var logo string
	logoRegex := regexp.MustCompile(`<link rel="(.*)?icon"(.*?)>`)
	submatchalllogo := logoRegex.FindAllStringSubmatch(formatedBody, -1)
	if len(submatchalllogo) > 0 && len(submatchalllogo[0]) > 0 {

		logoNameRegex := regexp.MustCompile(`("/.*?")|("http.*?")`)
		submatchalllogoname := logoNameRegex.FindAllStringSubmatch(submatchalllogo[0][0], -1)

		if len(submatchalllogoname) > 0 {
			logo = submatchalllogoname[0][0]
			logo = utf8Decode(logo[1 : len(logo)-1])
		}

	}

	// saveFile(formatedBody)

	return title, logo, nil
}

// get serverSSLGrade servers, SSLGradeMin, error
func getServers(domain string) ([]Server, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://api.ssllabs.com/api/v3/analyze?host=" + domain)

	fasthttp.Do(req, resp)

	bodyBytes := resp.Body()

	data := SSLResponse{}
	json.Unmarshal(bodyBytes, &data)

	servers := []Server{}

	for i := 0; i < len(data.Endpoints); i++ {
		server := Server{Address: data.Endpoints[i].IPAddress, SSLGrade: data.Endpoints[i].Grade}

		serverResult, err := whois.QueryHost(domain)
		if err != nil {
			fmt.Println("Error in server whois lookup :", err)
			return nil, err
		}
		if len(serverResult.Output["Registrant Country"]) > 0 {
			server.Country = serverResult.Output["Registrant Country"][0]
		}
		if len(serverResult.Output["Registrant Organization"]) > 0 {
			server.Owner = serverResult.Output["Registrant Organization"][0]
		}

		servers = append(servers, server)
	}

	return servers, nil
}

func utf8Decode(str string) string {
	var result string
	for i := range str {
		result += string(str[i])
	}
	return result
}

func validGrade(sslGrade string) bool {
	return sslGrade == "A+" || sslGrade == "A" || sslGrade == "A-" || sslGrade == "B" || sslGrade == "C" || sslGrade == "D" || sslGrade == "E"
}

// https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide
func getScore(sslGrade string) int {
	if sslGrade == "A+" {
		return 95
	} else if sslGrade == "A" {
		return 85
	} else if sslGrade == "A-" {
		return 80
	} else if sslGrade == "B" {
		return 65
	} else if sslGrade == "C" {
		return 50
	} else if sslGrade == "D" {
		return 35
	} else if sslGrade == "E" {
		return 20
	}
	return 0
}

func calculateMinSSLGrade(servers []Server) string {
	minSSLGrade := "A"
	min := 100
	for i := 0; i < len(servers); i++ {
		server := servers[i]
		curr := getScore(server.SSLGrade)
		valid := validGrade(server.SSLGrade)

		if valid && curr < min {
			min = curr
			minSSLGrade = server.SSLGrade
		}
	}
	return minSSLGrade
}

func insertDomainServersDB(domain *Domain) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")

	if err != nil {
		fmt.Println("error connecting to DB", err)
	}

	domain.PreviousSSLGrade = ""
	domain.SSLGrade = calculateMinSSLGrade(domain.Servers)
	domain.ServersChanged = false

	_, errInsDom := db.Exec(
		"INSERT INTO DB.Domain (Address, IsDown, Logo, SSLGrade, Title, LastUpdate) VALUES ($1, $2, $3, $4, $5, $6)", domain.Address, domain.IsDown, domain.Logo, domain.SSLGrade, domain.Title, time.Now())

	if errInsDom != nil {
		fmt.Println("error connecting to DB", errInsDom)
	}

	for i := 0; i < len(domain.Servers); i++ {
		server := domain.Servers[i]
		_, errInsSer := db.Exec(
			"INSERT INTO DB.Server (Address, SSLGrade, Country, Owner, DomainAddress, LastUpdate) VALUES ($1, $2, $3, $4, $5, $6)", server.Address, server.SSLGrade, server.Country, server.Owner, domain.Address, time.Now())
		if errInsSer != nil {
			fmt.Println("error", err)
		}
	}
	defer db.Close()
}

func updateDomainServersDB(domain *Domain) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")
	serversChanged := false

	if err != nil {
		fmt.Println("error connecting to DB", err)
	}

	for i := 0; i < len(domain.Servers); i++ {
		server := domain.Servers[i]
		exists, err := existsServerDB(server.Address)
		if err != nil {
			fmt.Println("error querying server in DB", err)
		}

		if exists {
			change := updateServerDB(&server)
			serversChanged = (serversChanged == false) && change
		} else {
			insertServerDB(server, domain)
		}

	}

	row := db.QueryRow("SELECT sslGrade, lastUpdate FROM DB.Domain WHERE Address = $1", domain.Address)
	if row != nil {
		var lastUpdate time.Time
		var sslGrade string

		err := row.Scan(&sslGrade, &lastUpdate)
		if err != nil {
			fmt.Println("error", err)
		}
		loc, _ := time.LoadLocation("UTC")
		now := time.Now().In(loc)
		diff := now.Sub(lastUpdate)

		if diff.Seconds() > 3600 {
			domain.PreviousSSLGrade = sslGrade
		}

		_, errupser := db.Exec(
			"UPDATE DB.Domain SET IsDown = $1, Logo = $2, SSLGrade = $3, Title = $4, LastUpdate = $5 WHERE Address = $6", domain.IsDown, domain.Logo, domain.SSLGrade, domain.Title, time.Now(), domain.Address)

		if errupser != nil {
			fmt.Println("error connecting to DB", errupser)
		}

	}

	domain.SSLGrade = calculateMinSSLGrade(domain.Servers)
	domain.ServersChanged = serversChanged

	defer db.Close()
}

// return if server has changed
func updateServerDB(server *Server) bool {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")
	var address string
	var country string
	var owner string
	var sslGrade string
	var lastUpdate time.Time
	var serverChanged bool

	if err != nil {
		fmt.Println("error connecting to DB", err)

	}

	row := db.QueryRow("SELECT Address, Country, Owner, SSLGrade, lastUpdate FROM DB.Server WHERE Address = $1", server.Address)
	if row != nil {
		err := row.Scan(&address, &country, &owner, &sslGrade, &lastUpdate)
		if err != nil {
			fmt.Println("error", err)
		}

		loc, _ := time.LoadLocation("UTC")
		now := time.Now().In(loc)
		diff := now.Sub(lastUpdate)

		serverChanged = diff.Seconds() > 3600 && ((server.Country != country) || (server.Owner != owner) || (server.SSLGrade != owner))

		_, errupser := db.Exec(
			"UPDATE DB.Server SET Country = $1, Owner = $2, SSLGrade = $3, LastUpdate = $4 WHERE Address = $5", server.Country, server.Owner, server.SSLGrade, time.Now(), server.Address)

		if errupser != nil {
			fmt.Println("error", errupser)
		}
	}

	defer db.Close()
	return serverChanged
}

func insertServerDB(server Server, domain *Domain) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")

	if err != nil {
		fmt.Println("error connecting to DB", err)
	}

	_, errInsConnection := db.Exec(
		"INSERT INTO DB.Server (Address, SSLGrade, Country, Owner, DomainAddress, LastUpdate) VALUES ($1, $2, $3, $4, $5, $6)", server.Address, server.SSLGrade, server.Country, server.Owner, domain.Address, time.Now())
	if errInsConnection != nil {
		fmt.Println("error", errInsConnection)
	}

	defer db.Close()
}

func insertConnectionDB(existsOrigin bool, host string, metaData string, domainAddress string) {
	db, err := sql.Open("postgres", "postgresql://"+IP+"/DB?sslmode=disable")

	if err != nil {
		fmt.Println("error connecting to DB", err)
	}

	if existsOrigin == false {

		_, errInsOrigin := db.Exec(
			"INSERT INTO DB.Origin (Address, Metadata, LastUpdate) VALUES ($1, $2, $3)", host, metaData, time.Now())

		if errInsOrigin != nil {
			fmt.Println("error", errInsOrigin)
		}
	}

	_, errInsConnection := db.Exec(
		"INSERT INTO DB.Connection (OriginIP, DomainAddress, LastUpdate) VALUES ($1, $2, $3)", host, domainAddress, time.Now())

	if errInsConnection != nil {
		fmt.Println("error", errInsConnection)
	}

	defer db.Close()
}

func saveFile(d string) {
	f, err := os.Create("example.html")
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	} else {
		f.WriteString(d)
		f.Close()
	}

}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}

	router := fasthttprouter.New()
	router.GET("/", IndexRoute)
	router.GET("/domain/:domain", DomainRoute)
	router.GET("/connections", ConnectionRoute)
	router.GET("/connections/:domain", ConnectionFilterRoute)

	log.Fatal(fasthttp.ListenAndServe(":"+port, router.Handler))
}
