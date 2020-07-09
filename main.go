package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"github.com/buaazp/fasthttprouter"
	whois "github.com/undiabler/golang-whois"
	"github.com/valyala/fasthttp"

	_ "github.com/lib/pq"
)

type Server struct {
	Address  string `json:"address"`
	SSLGrade string `json:"ssl_grade"`
	Country  string `json:"country"`
	Owner    string `json:"owner"`
}

type Domain struct {
	IsDown           bool     `json:"is_down"`
	Logo             string   `json:"logo"`
	PreviousSSLGrade string   `json:"previous_ssl_grade"`
	Server           []Server `json:"servers"`
	ServersChanged   bool     `json:"servers_changed"`
	SSLGrade         string   `json:"ssl_grade"`
	Title            string   `json:"title"`
}

func IndexRoute(ctx *fasthttp.RequestCtx) {
	fmt.Fprint(ctx, "Welcome to go backend!\n")
}

func DomainRoute(ctx *fasthttp.RequestCtx) {
	domain := ctx.UserValue("domain").(string)

	response, err := whoIsRequest(domain)

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

// whoIsRequest for domain and servers
func whoIsRequest(domain string) (Domain, error) {

	result, err := whois.GetWhois(domain)
	if err != nil {
		fmt.Println("Error in whois lookup :", err)
	} else {

		fmt.Println(result)

		fmt.Println("Nameservers: %v \n", whois.ParseNameServers(result))
		fmt.Println("Nameservers: %v \n")

	}

	response := Domain{IsDown: false}
	getDomainInfo(domain)

	return response, err
}

// Update domain, servers, origin, connection
func getDomainInfo(domain string) {
	ip := "3.85.23.204:26257"
	db, err := sql.Open("postgres", "postgresql://"+ip+"/DB?sslmode=disable")

	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	// Print out the Servers.
	rows, err := db.Query("SELECT Id, Address FROM DB.server")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	fmt.Println("Initial Servers:")
	for rows.Next() {
		var Id string
		var Address string
		if err := rows.Scan(&Id, &Address); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s %s\n", Id, Address)
	}

	defer db.Close()
}

func main() {
	router := fasthttprouter.New()
	router.GET("/", IndexRoute)
	router.GET("/info/:domain", DomainRoute)

	log.Fatal(fasthttp.ListenAndServe(":8090", router.Handler))
}
