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
	response, err := getDomainInfo(ctx)

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

func getDomainInfo(ctx *fasthttp.RequestCtx) (Domain, error) {
	var domainResponse Domain

	host := string(ctx.Request.Host())

	domain := ctx.UserValue("domain").(string)
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

		exists, err := existsDomainDB(domainAddress)

		if err != nil {
			log.Fatal("error querying domain in DB", err)
		}
		if exists == true {
			//Not supported yet
		} else if exists == false {
			insertDomainServersDB(&domainResponse)
		}

		existsOrigin, errOrigin := existsOriginDB(host)
		if errOrigin != nil {
			log.Fatal("error querying origin in DB", errOrigin)
		}
		insertConnectionDB(existsOrigin, host, "Some metadata", domainAddress)

	}

	return domainResponse, err
}

func existsDomainDB(domainAddress string) (bool, error) {
	ip := "carlos@34.201.170.228:26257"
	db, err := sql.Open("postgres", "postgresql://"+ip+"/DB?sslmode=disable")
	var address string

	if err != nil {
		log.Fatal("error connecting to the database: ", err)
		fmt.Println("Domains: ", "false")

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
	ip := "carlos@34.201.170.228:26257"
	db, err := sql.Open("postgres", "postgresql://"+ip+"/DB?sslmode=disable")
	var Address string

	if err != nil {
		log.Fatal("error connecting to the database: ", err)
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
	ip := "carlos@34.201.170.228:26257"
	db, err := sql.Open("postgres", "postgresql://"+ip+"/DB?sslmode=disable")

	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	domain.PreviousSSLGrade = calculateMinSSLGrade(domain.Servers)
	domain.SSLGrade = domain.PreviousSSLGrade
	domain.ServersChanged = false

	_, errInsDom := db.Exec(
		"INSERT INTO DB.Domain (Address, IsDown, Logo, SSLGrade, Title, LastUpdate) VALUES ($1, $2, $3, $4, $5, $6)", domain.Address, domain.IsDown, domain.Logo, domain.SSLGrade, domain.Title, time.Now())

	if errInsDom != nil {
		log.Fatal(errInsDom)
	}

	for i := 0; i < len(domain.Servers); i++ {
		server := domain.Servers[i]
		_, errInsSer := db.Exec(
			"INSERT INTO DB.Server (Address, SSLGrade, Country, Owner, DomainAddress, LastUpdate) VALUES ($1, $2, $3, $4, $5, $6)", server.Address, server.SSLGrade, server.Country, server.Owner, domain.Address, time.Now())
		if errInsSer != nil {
			log.Fatal(err)
		}
	}
	defer db.Close()
}

func insertConnectionDB(existsOrigin bool, host string, metaData string, domainAddress string) {
	ip := "carlos@34.201.170.228:26257"
	db, err := sql.Open("postgres", "postgresql://"+ip+"/DB?sslmode=disable")

	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}

	if existsOrigin == false {

		_, errInsOrigin := db.Exec(
			"INSERT INTO DB.Origin (Address, Metadata, LastUpdate) VALUES ($1, $2, $3)", host, metaData, time.Now())

		if errInsOrigin != nil {
			log.Fatal(errInsOrigin)
		}
	}

	_, errInsConnection := db.Exec(
		"INSERT INTO DB.Connection (OriginIP, DomainAddress, LastUpdate) VALUES ($1, $2, $3)", host, domainAddress, time.Now())

	if errInsConnection != nil {
		log.Fatal(errInsConnection)
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
