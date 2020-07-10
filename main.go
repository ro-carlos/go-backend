package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"github.com/buaazp/fasthttprouter"
	"github.com/valyala/fasthttp"
	"github.com/xellio/whois"

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

// PreviousSSLGrade and ServersChanged getCalculated in response
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

func IndexRoute(ctx *fasthttp.RequestCtx) {
	fmt.Fprint(ctx, "Welcome to go backend!\n")
}

func DomainRoute(ctx *fasthttp.RequestCtx) {
	domain := ctx.UserValue("domain").(string)

	response, err := getDomainInfo(domain)

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

func getDomainInfo(domain string) (Domain, error) {
	var domainResponse Domain

	domainResult, err := whois.QueryHost(domain)
	if err != nil {
		fmt.Println("Error in whois lookup :", err)
	} else {
		domainAddress := domainResult.Output["Domain Name"][0]
		domainCountry := domainResult.Output["Registrant Country"][0]
		domainOwner := domainResult.Output["Registrant Organization"][0]
		// domainServers := domainResult.Output["Name Server"]
		domainIsDown := domainResult.Output["status"][0]
		domainServers, err := getServers(domain)
		if err != nil {
			log.Fatal("error getting servers ", err)
		}

		fmt.Println("Address: ", domainAddress)
		fmt.Println("Country: ", domainCountry)
		fmt.Println("Owner: ", domainOwner)
		fmt.Println("Servers: ", domainServers)
		fmt.Println("isDown: ", domainIsDown)

		domainResponse = Domain{IsDown: false, Servers: domainServers}

	}

	return domainResponse, err
}

// get serverSSLGrade ervers, SSLGradeMin, error
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

// Update domain, servers, origin, connection
func queryDBInfo(domain string) {
	ip := "carlos@54.86.13.212:26257"
	db, err := sql.Open("postgres", "postgresql://"+ip+"/DB?sslmode=disable")

	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	// Print out the Servers.
	rows, err := db.Query("SELECT Address, LastUpdate FROM DB.server")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	fmt.Println("Initial Servers from DB:")
	for rows.Next() {
		var Address string
		var LastUpdate string
		if err := rows.Scan(&Address, &LastUpdate); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s %s\n", Address, LastUpdate)
	}

	defer db.Close()
}

func main() {
	router := fasthttprouter.New()
	router.GET("/", IndexRoute)
	router.GET("/info/:domain", DomainRoute)

	log.Fatal(fasthttp.ListenAndServe(":8090", router.Handler))
}
