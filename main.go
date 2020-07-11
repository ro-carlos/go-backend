package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"

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
		domainServers, err := getServers(domain)
		if err != nil {
			log.Fatal("error getting servers ", err)
		}

		domainTitle, domainLogo, err := getTitleLogo(domain)
		if err != nil {
			log.Fatal("error title and logo ", err)
		}

		var domainIsDown bool
		if domainResult.Output["status"][0] == "ACTIVE" {
			domainIsDown = false
		} else {
			domainIsDown = true
		}

		domainResponse = Domain{Address: domainAddress, IsDown: domainIsDown, Logo: domainLogo,
			Servers: domainServers, Title: domainTitle}

	}

	return domainResponse, err
}

// get title and logo from specific domain
func getTitleLogo(domain string) (string, string, error) {
	url := "http://" + domain
	statusCode, body, err := fasthttp.Get(nil, url)

	if err != nil {
		log.Fatal("Error in getTitleLogo :", statusCode, err)
		return "", "", err
	}

	formatedBody := string(body)

	var title string
	titleRegex := regexp.MustCompile(`<title.*?>(.*)</title>`)
	submatchalltitle := titleRegex.FindAllStringSubmatch(formatedBody, -1)
	if len(submatchalltitle) > 0 && len(submatchalltitle[0]) > 1 {
		title = submatchalltitle[0][1]
	}

	var logo string
	logoRegex := regexp.MustCompile(`<link rel="(.*)?icon"(.*?)>`)
	submatchalllogo := logoRegex.FindAllStringSubmatch(formatedBody, -1)
	if len(submatchalllogo) > 0 && len(submatchalllogo[0]) > 0 {

		logoNameRegex := regexp.MustCompile(`("/.*?")|("http.*?")`)
		submatchalllogoname := logoNameRegex.FindAllStringSubmatch(submatchalllogo[0][0], -1)

		if len(submatchalllogoname) > 0 {
			logo = submatchalllogoname[0][0]
			logo = logo[1 : len(logo)-1]
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

// Update domain, servers, origin, connection
func queryDBInfo(domain string) {
	ip := "carlos@54.172.113.54:26257"
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
	router := fasthttprouter.New()
	router.GET("/", IndexRoute)
	router.GET("/info/:domain", DomainRoute)

	log.Fatal(fasthttp.ListenAndServe(":8090", router.Handler))
}
