package main

import (
	"bytes"
	"database/sql"
	"encoding/json" //libreria para codificar y decodificar json
	"fmt"
	_ "fmt" // no more error
	"log"
	"net"
	"strings"

	"github.com/badoux/goscraper" //libreria para obtener datos del head de la página
	"github.com/buaazp/fasthttprouter"

	//libreria para el router
	"github.com/likexian/whois-go" //libreria para comando whois
	"github.com/valyala/fasthttp"  //libreria para las conexiones http

	_ "github.com/lib/pq" // libreria para la base de datos (postgres driver)
)

//ESTRUCTURAS A UTILIZAR
//Estructuras para los endpoints
// estructura de datos para enviar el JSON con informacion de los servidores
type Data struct {
	Servers []struct {
		Address  string `json:"address"`
		Sslgrade string `json:"sslgrade"`
		Country  string `json:"country"`
		Owner    string `json:"owner"`
	} `json:"servers"`
	ServersChanged   bool   `json:"servers_changed"`
	SslGrade         string `json:"ssl_grade"`
	PreviousSslGrade string `json:"previous_ssl_grade"`
	Logo             string `json:"logo"`
	Title            string `json:"title"`
	IsDown           bool   `json:"is_down"`
}

//Estructura de datos para obtener los datos de ssllabs.com (Json data from ssllabs.com)
type SSLabs struct {
	Host            string `json:"host"`
	Port            int    `json:"port"`
	Protocol        string `json:"protocol"`
	IsPublic        bool   `json:"isPublic"`
	Status          string `json:"status"`
	StartTime       int64  `json:"startTime"`
	TestTime        int64  `json:"testTime"`
	EngineVersion   string `json:"engineVersion"`
	CriteriaVersion string `json:"criteriaVersion"`
	Endpoints       []struct {
		IPAddress         string `json:"ipAddress"`
		ServerName        string `json:"serverName"`
		StatusMessage     string `json:"statusMessage"`
		Grade             string `json:"grade"`
		GradeTrustIgnored string `json:"gradeTrustIgnored"`
		HasWarnings       bool   `json:"hasWarnings"`
		IsExceptional     bool   `json:"isExceptional"`
		Progress          int    `json:"progress"`
		Duration          int    `json:"duration"`
		Delegation        int    `json:"delegation"`
	} `json:"endpoints"`
}

//Estructura para el JSON enviado al cliente (informacion almacenada en la base de datos)
type Row struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Grade string `json:"grade"`
}
type Table struct {
	Row []Row `json:"items"`
}

//Estructura para mostrar el html en el index
type PageData struct {
	Title string
}

//FUNCIONES DE LA BASE DE DATOS
//---------------------------------------------------------------------------------------

//Función para conectar con la base de datos
func conDB() *sql.DB {
	// conectar a la base de datos llamada "servers_db"
	db, err := sql.Open("postgres", "postgresql://root@localhost:26257/servers_db?sslmode=disable")
	if err != nil {
		log.Fatal("error connecting to the database: ", err)
	}
	return db
}

//Función para crear la base de datos
func migrateDB(db *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS "tbl_servers" (
		"server_id" SERIAL,
		"domain" STRING(100),
		"grade" STRING(50),
		"created_at" TIMESTAMPTZ,
		"updated_at" TIMESTAMPTZ,
		PRIMARY KEY ("server_id")
	);`

	if _, err := db.Exec(query); err != nil {
		log.Fatal(err)
	}
}

//Función para hacer traer los datos de la base de datos
func selectDB(db *sql.DB) Table {
	rows, err := db.Query("select server_id, domain,grade FROM tbl_servers;")
	if err != nil {
		log.Fatal(err)
	}

	defer rows.Close()

	table := Table{} //crear una nueva tabla

	for rows.Next() {
		row := Row{} //crear una nueva fila

		err := rows.Scan(&row.ID, &row.Name, &row.Grade) //leer y guardas los datos de la base de datos
		if err != nil {
			panic(err)
		}

		table.Row = append(table.Row, row)

	}
	return table
}

//Función para insertar a la tabla de la base de datos
func insertDB(db *sql.DB, domain string, grade string) {
	// insertar una fila en la tabla "tbl_servers"

	if _, err := db.Exec(
		`INSERT INTO tbl_servers (domain, grade, created_at, updated_at) 
			VALUES ('` + domain + `','` + grade + `', NOW(), NOW());`); err != nil {
		log.Fatal(err)
	}
}

//Función para actualizar la base de datos
func updateDB(db *sql.DB, grade string, domain string) {
	var query string
	query = "UPDATE tbl_servers SET grade = '" + grade + "', updated_at =NOW() WHERE domain='" + domain + "';"
	if _, err := db.Exec(query); err != nil {
		log.Fatal(err)
	}
}

//Función para saber si el dominio ya existe en la base de datos
func existRow(db *sql.DB, domain string) bool {
	var query string
	var valor bool

	query = "select exists(select 1 from tbl_servers where domain='" + domain + "');"
	rows, err := db.Query(query)

	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&valor); err != nil {
			log.Fatal(err)
		}
	}
	return valor
}

//FUNCIONES PARA LOS ENDPOINTS
//---------------------------------------------------------------------------------------

//funcion para encontrar el grado anterior
func getPGrade(db *sql.DB, domain string) string {
	var rowE bool
	var grade string
	grade = ""
	rowE = existRow(db, domain)
	if rowE == true {
		rows, err := db.Query("select grade FROM tbl_servers WHERE domain='" + domain + "';")

		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			if err := rows.Scan(&grade); err != nil {
				log.Fatal(err)
			}
		}
	}
	return grade
}

//Función para obtener la ip del servidor (comando whois)
func getIp(dom string) []string {
	addr, err := net.LookupIP(dom)
	var Ips []string //arreglo para todas las IPs encontradas asociadas al dominio
	if err != nil {
		fmt.Println("Unknown host")
	} else {

		for i := 0; i < len(addr); i++ {

			Ips = append(Ips, addr[i].String()) //agregar datos al arreglo (slice)
		}
	}
	return Ips
}

//Función para obtener la IP del hostname (con la estructura)
func getServersName(s SSLabs) []string {
	var serverNames []string
	for i := 0; i < len(s.Endpoints); i++ {
		serverNames = append(serverNames, s.Endpoints[i].ServerName)
	}

	return serverNames
}

func getAllGrades(s SSLabs) []string {
	var grades []string
	for i := 0; i < len(s.Endpoints); i++ {
		grades = append(grades, s.Endpoints[i].Grade)
	}

	return grades
}

//Función para obtener el sslgrade mas bajo de todos los servidores
func getSSLGradeMenor(s SSLabs) string {

	var grades []string                 //todos los grados
	var mengrade = s.Endpoints[0].Grade //el grado menor

	//guardar los grades en un arreglo para compararlos
	grades = getAllGrades(s)

	for i := 0; i < len(grades); i++ {
		if grades[i] < mengrade {
			mengrade = mengrade
		}
	}
	return mengrade
}

//Función para obtener el pais del servidor
func getCountry(Ip string) string {
	var line, country string
	result, err := whois.Whois(Ip)
	if err == nil {
		testArray := strings.Split(result, "\n")
		for i := 0; i < len(testArray); i++ {
			if strings.Contains(testArray[i], "Country") {
				line = testArray[i] //obtener la linea donde esta el país
				break
			}
		}
		testArray2 := strings.Split(line, ":        ")
		country = testArray2[1]
	}
	return country
}

//Función para obtener el pais del servidor
func getOwner(Ip string) string {
	var line, owner string
	result, err := whois.Whois(Ip)
	if err == nil {
		testArray := strings.Split(result, "\n")
		for i := 0; i < len(testArray); i++ {
			if strings.Contains(testArray[i], "OrgName") {
				line = testArray[i] //obtener la linea donde esta el dueño
				break

			}
		}
		testArray2 := strings.Split(line, ":        ")
		owner = testArray2[1]
	}

	return owner
}

//Función paa obtener el logo de una pagina
func getLogo(d string) string {
	s, err := goscraper.Scrape(d, 5)
	if err != nil {
		fmt.Println(err)
		return "ocurrio un error"
	} else {
		return s.Preview.Icon
	}

}

//Función para obtener el titulo de una pagina
func getTitle(d string) string {
	s, err := goscraper.Scrape(d, 5)
	if err != nil {
		fmt.Println(err)
		return "ocurrio un error"
	} else {
		return s.Preview.Title
	}

}

//Función para saber si un servidor esta caido
func serverDown(url string) string {
	var serverDown string
	serverDown = "false"

	statusCode, body, err := fasthttp.Get(nil, url)
	_ = body
	// capturar el error, si hay uno
	if err != nil {
		log.Fatalf("Error when loading google page through local proxy: %s", err)
	}
	if statusCode != fasthttp.StatusOK {
		log.Fatalf("Unexpected status code: %d. Expecting %d", statusCode, fasthttp.StatusOK)
	}

	if statusCode == 503 {
		serverDown = "true"
	}
	return serverDown
}

//Endpoint (1) que toma el dominio solicitado, obtiene los datos y regresa un json
func infoServers(ctx *fasthttp.RequestCtx) {
	//fmt.Fprintf(ctx, "el hostname es :%s\n", ctx.UserValue("hostname")) //esto se reemplaza cuando se devuelva el json

	str := fmt.Sprintf("%v", ctx.UserValue("hostname")) //obtener el hostname y convertirlo de interface a string

	//la url para obtener los datos del dominio
	url := "https://api.ssllabs.com/api/v3/analyze?host=" + str

	//obtener el body de la url
	statusCode, body, err := fasthttp.Get(nil, url) //funcion similar a resp, err := http.Get(url)

	// capturar el error, si hay uno
	if err != nil {
		log.Fatalf("Error when loading google page through local proxy: %s", err)
	}
	if statusCode != fasthttp.StatusOK {
		log.Fatalf("Unexpected status code: %d. Expecting %d", statusCode, fasthttp.StatusOK)
	}

	//-------------------------------------------------------------------------------------------------
	// OBTENER TODA LA INFORMACIÓN DEL DOMINIO Y GUARDANDOLA EN VARIABLES

	var SSlabs1 SSLabs
	r := bytes.NewReader(body) //convertir bytes to io.reader

	err2 := json.NewDecoder(r).Decode(&SSlabs1) //codificar el io.reader a json y guardarlo en la estructura

	if err2 != nil {
		log.Fatalf("Unexpected error")
	}

	//Obtener los servidores asociados a ese hostname (un slice con los nombres)
	var serversNames []string
	serversNames = getServersName(SSlabs1) //slice con el nombre de los servidores asociados al dominio

	//Obtener dirección Ip de los servidores asociados a ese hostname (un slice con las Ips)

	var IpsServers []string
	for i := 0; i < len(serversNames); i++ {
		ip := getIp(serversNames[i])
		IpsServers = append(IpsServers, ip[0])

	}

	//Obtener el grado de los servidores asociados a es hostname (un slice)

	var grades []string
	grades = getAllGrades(SSlabs1)

	//obtener el país de los servidores asociados al hostname (como aparece en WHOIS)

	var countries []string

	for j := 0; j < len(IpsServers); j++ {
		countries = append(countries, getCountry(IpsServers[j]))
	}

	//Obtener el dueño de los servidores asociados al hostname (como aparece en WHOIS)

	var owners []string

	for k := 0; k < len(IpsServers); k++ {
		owners = append(owners, getOwner(IpsServers[k]))
	}

	//obtener el grado menor de todos los servidores
	var menorGrade string
	menorGrade = getSSLGradeMenor(SSlabs1)

	//obtener el logo y titulo de la pagina
	var domain, title, logo string
	domain = "https://www." + str
	title = getTitle(domain)
	logo = getLogo(domain)

	//saber si el servidor esta caido
	var serverIsDown string
	serverIsDown = serverDown(domain)

	domainName := strings.ToLower(str) //nombre del dominio (por si el usuario lo escribe en mayusculas)

	var db *sql.DB //base de datos
	db = conDB()   //conexión a la base de datos

	//grado anterior
	var previousGrade string
	previousGrade = getPGrade(db, domainName)

	db.Close()

	//-------------------------------------------------------------------------------------------------
	// CREANDO EL JSON PARA ENVIAR AL CLIENTE

	//crear un texto de los datos a enviar como json
	var text string
	text = `{"servers": [`
	for p := 0; p < len(serversNames); p++ {
		if p+1 == len(serversNames) {
			text = text + `{"address": "` + IpsServers[p] + `", "sslgrade": "` + grades[p] + `","country": "` + countries[p] + `","owner": "` + owners[p] + `"} `
		} else {
			text = text + `{"address": "` + IpsServers[p] + `", "sslgrade": "` + grades[p] + `","country": "` + countries[p] + `","owner": "` + owners[p] + `"}, `
		}

	}

	//FALTA!!! SERVER_CHANGED, PREVIOUSLY SSL GRADE

	text = text + `], "servers_changed": ` + "true" + `,"ssl_grade" : "` + menorGrade + `","previous_ssl_grade": "` + previousGrade + `","logo": "` + logo + `","title": "` + title + `","is_down":` + serverIsDown + `}`

	textBytes := []byte(text) //convertir el texto a bytes
	data1 := Data{}           //crear una instancia de la estructura para los datos

	errjson := json.Unmarshal(textBytes, &data1) //guardar información en la estructura de datos
	if errjson != nil {
		fmt.Println(errjson)
		return
	}

	json.NewEncoder(ctx).Encode(data1) //enviar el json al cliente

	//-------------------------------------------------------------------------------------------------
	//----INSERTAR INFORMACIÓN A LA BASE DE DATOS PARA PODER CONSULTARLA POSTERIORMENTE
	db = conDB() //conexión a la base de datos

	// insertar una fila en la tabla "tbl_servers"
	var valor bool
	valor = existRow(db, domainName)
	if valor != true {
		insertDB(db, domainName, menorGrade)
	} else {
		updateDB(db, menorGrade, domainName)
	}

	db.Close()

}

//Endpoint (2) listar los servidores que han sido consultados
func allServers(handler fasthttp.RequestHandler, db *sql.DB) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {

		ctx.SetContentType("application/json") //para que se muestre json

		table := Table{} //crear una nueva tabla

		table = selectDB(db)

		json.NewEncoder(ctx).Encode(table) //enviar el json al cliente

		handler(ctx)
	}
}

// the error handler
func error(ctx *fasthttp.RequestCtx) {

	//fmt.Fprint(ctx, "Ocurrió un error!\n")
}

func Index(ctx *fasthttp.RequestCtx) {
	//ctx.SetContentType("text/html") //para que se muestre como html

	ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "authorization")
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "HEAD,GET,POST,PUT,DELETE,OPTIONS")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	ctx.SendFile("./public/index.html")
}

//POST: enviar datos del cliente al servidor
//GET: el navegador quiere obtener algo del servidor
func main() {

	var db *sql.DB
	db = conDB()  //se conecta a la base de datos
	migrateDB(db) //se crea la tabla de servidores si no existe.

	router := fasthttprouter.New() // API Router: fasthttprouter

	router.GET("/", Index)                            //index donde se muestra la interfaz
	router.GET("/infoservers/:hostname", infoServers) //consultar la informacion de un dominio
	router.GET("/servers", allServers(error, db))     // listar los servidores consultados

	//router.ServeFiles("/static/*filepath", "static")

	log.Fatal(fasthttp.ListenAndServe(":8081", router.Handler))

}
