package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
)

var errorregexes = []string{
	"SQL error.*?POS([0-9]+)",
	"Warning.*?\\Wmaxdb_",
	"DriverSapDB",
	"com\\.sap\\.dbtech\\.jdbc",
	"SQL syntax.*?MySQL",
	"Warning.*?\\Wmysqli?_",
	"MySQLSyntaxErrorException",
	"valid MySQL result",
	"check the manual that corresponds to your (MySQL|MariaDB) server version",
	"Unknown column '[^ ]+' in 'field list'",
	"MySqlClient\\.",
	"com\\.mysql\\.jdbc",
	"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
	"Pdo[./_\\\\]Mysql",
	"MySqlException",
	"Exception (condition )?\\d+\\. Transaction rollback",
	"com\\.frontbase\\.jdbc",
	"org\\.h2\\.jdbc",
	"Unexpected end of command in statement \\[",
	"Unexpected token.*?in statement \\[",
	"org\\.hsqldb\\.jdbc",
	"SQLite/JDBCDriver",
	"SQLite\\.Exception",
	"(Microsoft|System)\\.Data\\.SQLite\\.SQLiteException",
	"Warning.*?\\W(sqlite_|SQLite3::)",
	"\\[SQLITE_ERROR\\]",
	"SQLite error \\d+:",
	"sqlite3.OperationalError:",
	"SQLite3::SQLException",
	"org\\.sqlite\\.JDBC",
	"Pdo[./_\\]Sqlite",
	"SQLiteException",
	"Microsoft Access (\\d+ )?Driver",
	"JET Database Engine",
	"Access Database Engine",
	"ODBC Microsoft Access",
	"Syntax error \\(missing operator\\) in query expression",
	"Driver.*? SQL[\\-\\_\\ ]*Server",
	"OLE DB.*? SQL Server",
	"\\bSQL Server[^&lt;&quot;]+Driver",
	"Warning.*?\\W(mssql|sqlsrv)_",
	"\\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
	"System\\.Data\\.SqlClient\\.SqlException",
	"(?s)Exception.*?\\bRoadhouse\\.Cms\\.",
	"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
	"\\[SQL Server\\]",
	"ODBC SQL Server Driver",
	"ODBC Driver \\d+ for SQL Server",
	"SQLServer JDBC Driver",
	"com\\.jnetdirect\\.jsql",
	"macromedia\\.jdbc\\.sqlserver",
	"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
	"com\\.microsoft\\.sqlserver\\.jdbc",
	"Pdo[./_\\](Mssql|SqlSrv)",
	"SQL(Srv|Server)Exception",
	"\\bORA-\\d{5}",
	"Oracle error",
	"Oracle.*?Driver",
	"Warning.*?\\W(oci|ora)_",
	"quoted string not properly terminated",
	"SQL command not properly ended",
	"macromedia\\.jdbc\\.oracle",
	"oracle\\.jdbc",
	"Zend_Db_(Adapter|Statement)_Oracle_Exception",
	"Pdo[./_\\\\](Oracle|OCI)",
	"OracleException",
	"PostgreSQL.*?ERROR",
	"Warning.*?\\Wpg_",
	"valid PostgreSQL result",
	"Npgsql\\.",
	"PG::SyntaxError:",
	"org\\.postgresql\\.util\\.PSQLException",
	"ERROR:\\s\\ssyntax error at or near",
	"ERROR: parser: parse error at or near",
	"PostgreSQL query failed",
	"org\\.postgresql\\.jdbc",
	"Pdo[./_\\\\]Pgsql",
	"PSQLException"}

var transport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Second,
		DualStack: true,
	}).DialContext,
}

var httpClient = &http.Client{
	Transport: transport,
}

func main() {
	var threads int
	var wg sync.WaitGroup
	urls := make(chan string)
	flag.IntVar(&threads, "t", 20, "Specify number of threads to use")
	flag.Parse()

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go workers(urls, &wg)
	}

	input := bufio.NewScanner(os.Stdin)
	for input.Scan() {
		//Check if there has params
		parsed, err := url.Parse(input.Text())
		if err != nil {
			continue
		}
		if len(parsed.Query()) == 0 {
			continue
		}
		urls <- input.Text()
	}
	close(urls)
	wg.Wait()
}

func checksqli(s string) {
	//Heuristic
	//var wg sync.WaitGroup
	if heuristic(s) {
		fmt.Println(s, "is vulnerable to sqli")
		return
	}

}

func changeparams(s string, value string) string {
	var count int
	parsed, err := url.Parse(s)
	if err != nil {
		return ""
	}
	base := parsed.Scheme + "://" + parsed.Host + parsed.Path + "?"
	for a, b := range parsed.Query() {
		if count == len(parsed.Query())-1 {
			base = base + a + "=" + b[0] + value
		} else {
			base = base + a + "=" + b[0] + value + "&"
		}
		count++
	}
	return base
}

func heuristic(s string) bool {
	resp, err := httpClient.Get(changeparams(s, "'"))
	if err != nil {
		return false
	}
	body, _ := ioutil.ReadAll(resp.Body)
	yeet := string(body)
	resp.Body.Close()
	for _, i := range errorregexes {
		r, err := regexp.Compile(i)
		if err != nil {
			continue
		}
		found := r.FindAllString(yeet, -1)
		if len(found) != 0 {
			return true
		}
	}
	return false
}

func workers(cha chan string, wg *sync.WaitGroup) {
	for i := range cha {
		checksqli(i)
	}
	wg.Done()
}
