package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"golang.org/x/net/proxy"
)

// --- ESTILOS UI ---
var (
	styleBanner   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5555")).MarginBottom(1)
	styleSuccess  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#50FA7B"))
	styleWarning  = lipgloss.NewStyle().Foreground(lipgloss.Color("#F1FA8C"))
	styleInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD"))
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4"))
	styleError    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5555"))
	styleTime     = lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9"))
	styleIP       = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6"))
	styleLatency  = lipgloss.NewStyle().Foreground(lipgloss.Color("#F1FA8C"))
	styleSize     = lipgloss.NewStyle().Foreground(lipgloss.Color("#8BE9FD"))
	styleWords    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB86C"))
	styleLines    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF79C6"))
	styleTitle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#F8F8F2"))
	styleCrit     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5555"))
	styleTakeover = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF00FF"))
	styleProgress = lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B"))
)

type multiArg []string

func (m *multiArg) String() string         { return strings.Join(*m, ", ") }
func (m *multiArg) Set(value string) error { *m = append(*m, value); return nil }

// --- ESTRUCTURAS ---
type Config struct {
	URL             string
	Wordlists       multiArg // Soporte para múltiples wordlists (-w w1.txt -w w2.txt)
	Threads         int
	Mode            string // "dir", "vhost", "dns"
	Resolver        string
	ProxyList       string
	Recursion       bool
	MaxDepth        int
	AutoCalibrate   bool
	SmartEncode     bool
	Extensions      string
	Resume          string
	RandomAgent     bool
	Headers         multiArg
	Method          string
	Data            string
	Rate            int
	Timeout         int
	Retries         int
	FollowRedirects bool
	Output          string
	OutputJson      bool
	Silent          bool
	Verbose         bool
	NoColor         bool

	// Filtros y Matches (múltiples valores por coma)
	MatchStatus  string
	FilterStatus string
	MatchSize    string
	FilterSize   string
	MatchWords   string
	FilterWords  string
	MatchLines   string
	FilterLines  string
	MatchText    string
	FilterText   string
	MatchRegex   string
	FilterRegex  string
}

type Result struct {
	Payloads    map[string]string `json:"payloads"` // Ej: {"FUZZ": "admin", "FUZ2Z": "123"}
	Status      int               `json:"status"`
	Size        int64             `json:"size"`
	Words       int               `json:"words"`
	Lines       int               `json:"lines"`
	URL         string            `json:"url"`
	ContentType string            `json:"content_type,omitempty"`
	IP          string            `json:"ip,omitempty"`
	Latency     int64             `json:"latency_ms"`
	Timestamp   string            `json:"timestamp"`
	Title       string            `json:"title,omitempty"`
	Depth       int               `json:"depth,omitempty"`
	IsCritical  bool              `json:"is_critical,omitempty"`
	PotTakeover bool              `json:"potential_takeover,omitempty"`
	CNAME       string            `json:"cname,omitempty"`
	IsDir       bool              `json:"is_dir,omitempty"`
	Filtered    bool              `json:"filtered,omitempty"` // Si fue filtrado, para modo verbose
	Body        []byte            `json:"-"`
}

type RequestTask struct {
	Payloads  map[string]string
	TargetURL string
	Depth     int
}

type RecTask struct {
	BaseURL string
	Depth   int
}

type Session struct {
	Config    Config `json:"config"`
	Timestamp string `json:"timestamp"`
	Index     int64  `json:"index"`
}

type CalibrationData struct {
	Statuses map[int]bool
	Sizes    map[int64]bool
	Words    map[int]bool
	Lines    map[int]bool
}

// --- VARIABLES GLOBALES ---
var (
	config        Config
	client        *http.Client
	totalReq      atomic.Int64
	completedReq  atomic.Int64
	totalPayloads int64
	startTime     time.Time

	recTasks        chan RecTask
	resultsChan     chan Result
	sessionPath     string
	outputFile      *os.File
	csvWriter       *csv.Writer
	fileMu          sync.Mutex
	rateLimiter     <-chan time.Time
	filterRegComp   *regexp.Regexp
	matchRegComp    *regexp.Regexp
	globalResolver  *net.Resolver
	baseDomain      string
	proxies         []string
	proxyIndex      atomic.Uint64
	resumeIndex     int64
	loadedWordlists [][]string

	calibData = CalibrationData{
		Statuses: make(map[int]bool),
		Sizes:    make(map[int64]bool),
		Words:    make(map[int]bool),
		Lines:    make(map[int]bool),
	}
	calibMu    sync.Mutex
	errorCount atomic.Int64

	criticalFiles  = []string{".env", ".git", "id_rsa", "id_dsa", ".htpasswd", ".htaccess", "wp-config.php", "web.config", "database.yml", "backup.sql", ".bash_history"}
	takeoverCNAMEs = []string{"awsapps.com", "herokuapp.com", "github.io", "cloudfront.net", "elasticbeanstalk.com", "s3.amazonaws.com", "zendesk.com", "shopify.com", "fastly.net", "pantheon.io", "ghost.io", "azurewebsites.net"}
	titleRegex     = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	userAgents     []string
	dirStats       = make(map[string]map[int64]int)
	dirStatsMu     sync.Mutex
	consoleMu      sync.Mutex
	progressActive bool

	// Matchers y Filters transformados
	matchStatusMap  = make(map[int]bool)
	filterStatusMap = make(map[int]bool)

	// Flags por defecto fijos
	defaultMatchStatus = "200,204,301,302,307,308,401,403,405,500"
)

const (
	clearLine = "\r\x1b[2K"
	version   = "5.7"
)

func main() {
	flagSet := flag.NewFlagSet("fux", flag.ExitOnError)
	flagSet.StringVar(&config.URL, "u", "", "URL Objetivo (usa FUZZ, FUZ2Z, etc.)")
	flagSet.Var(&config.Wordlists, "w", "Wordlist o generador. Ej: -w w1.txt -w w2.txt")
	flagSet.IntVar(&config.Threads, "t", 5, "Hilos concurrentes")
	flagSet.StringVar(&config.Mode, "mode", "dir", "Modo de operación: dir, vhost, dns")
	flagSet.StringVar(&config.Resolver, "r", "", "DNS personalizado (ej. 8.8.8.8)")
	flagSet.StringVar(&config.ProxyList, "p", "", "Lista de proxies (http/socks5)")
	flagSet.BoolVar(&config.Recursion, "rec", false, "Recursividad inteligente (solo en dir mode)")
	flagSet.IntVar(&config.MaxDepth, "md", 3, "Profundidad máxima para recursividad")
	flagSet.BoolVar(&config.AutoCalibrate, "ac", false, "Auto-calibrar falsos positivos (404s/200s anómalos)")
	flagSet.BoolVar(&config.SmartEncode, "se", false, "Evasión WAF en 403")
	flagSet.StringVar(&config.Extensions, "x", "", "Extensiones separadas por coma (ej. php,html)")
	flagSet.StringVar(&config.Resume, "res", "", "Reanudar sesión desde archivo")
	flagSet.BoolVar(&config.RandomAgent, "ra", false, "Rotar User-Agent automáticamente")
	flagSet.Var(&config.Headers, "H", "Header personalizado (-H 'X-API: FUZZ')")
	flagSet.StringVar(&config.Method, "X", "GET", "Método HTTP")
	flagSet.StringVar(&config.Data, "d", "", "Body data (ej. 'user=admin&pass=FUZZ')")
	flagSet.IntVar(&config.Rate, "rate", 0, "Rate limit (peticiones/segundo, 0=sin límite)")
	flagSet.IntVar(&config.Timeout, "timeout", 10, "Timeout por petición en segundos")
	flagSet.IntVar(&config.Retries, "retries", 0, "Reintentos automáticos en caso de error")
	flagSet.BoolVar(&config.FollowRedirects, "follow", false, "Seguir redirecciones (HTTP)")

	// Salida
	flagSet.StringVar(&config.Output, "o", "", "Exportar resultados a archivo (.json o .csv)")
	flagSet.BoolVar(&config.OutputJson, "oj", false, "Forzar salida JSONL en archivo y stdout")
	flagSet.BoolVar(&config.Silent, "silent", false, "Modo silencioso (solo resultados)")
	flagSet.BoolVar(&config.Verbose, "v", false, "Modo detallado (muestra resultados filtrados)")
	flagSet.BoolVar(&config.NoColor, "no-color", false, "Desactivar colores")

	// Matches y Filters
	flagSet.StringVar(&config.MatchStatus, "mc", defaultMatchStatus, "Match por código de estado (ej. 200,204,301)")
	flagSet.StringVar(&config.FilterStatus, "fc", "404", "Filtrar por código de estado (ej. 404,400)")
	flagSet.StringVar(&config.MatchWords, "mw", "", "Match por cantidad de palabras")
	flagSet.StringVar(&config.FilterWords, "fw", "", "Filtrar por cantidad de palabras")
	flagSet.StringVar(&config.MatchLines, "ml", "", "Match por cantidad de líneas")
	flagSet.StringVar(&config.FilterLines, "fl", "", "Filtrar por cantidad de líneas")
	flagSet.StringVar(&config.MatchSize, "ms", "", "Match por tamaño/rango (ej. 100-200)")
	flagSet.StringVar(&config.FilterSize, "fs", "", "Filtrar por tamaño/rango")
	flagSet.StringVar(&config.MatchText, "mt", "", "Match por texto en la respuesta")
	flagSet.StringVar(&config.FilterText, "ft", "", "Filtrar por texto en la respuesta")
	flagSet.StringVar(&config.MatchRegex, "mr", "", "Match por Regex en la respuesta")
	flagSet.StringVar(&config.FilterRegex, "fr", "", "Filtrar por Regex en la respuesta")
	var showVersion bool
	flagSet.BoolVar(&showVersion, "version", false, "Mostrar versión y salir")

	flagSet.Parse(os.Args[1:])

	if showVersion {
		fmt.Printf("fux v%s\n", version)
		os.Exit(0)
	}

	config.Mode = strings.ToLower(strings.TrimSpace(config.Mode))
	if config.Mode != "dir" && config.Mode != "vhost" && config.Mode != "dns" {
		config.Mode = "dir"
	}

	if config.Mode != "dns" && config.URL != "" {
		if !strings.HasPrefix(config.URL, "http://") && !strings.HasPrefix(config.URL, "https://") {
			config.URL = "https://" + config.URL
		}
	}

	config.Method = strings.ToUpper(strings.TrimSpace(config.Method))

	for _, h := range config.Headers {
		if !strings.Contains(h, ":") {
			log.Fatalf("Formato de cabecera inválido: %q. Debe tener el formato 'Nombre: Valor'", h)
		}
	}

	if config.Threads <= 0 {
		log.Fatalf("El número de hilos (-t) debe ser mayor que 0")
	}

	if config.Timeout <= 0 {
		config.Timeout = 10
	}

	if config.Mode == "dns" && config.URL != "" && !strings.Contains(config.URL, "FUZZ") {
		config.URL = "FUZZ." + strings.TrimPrefix(config.URL, ".")
	}

	if config.NoColor || config.Silent || config.OutputJson {
		disableColors()
	}

	if config.URL == "" && config.Resume == "" {
		if !config.Silent {
			printHelp()
		}
		os.Exit(1)
	}

	if len(config.Wordlists) == 0 && config.Resume == "" {
		log.Fatal("Se debe especificar al menos una wordlist con -w (o reanudar sesión con -res)")
	}

	initUserAgents()
	parseFilters()

	if config.Resume != "" {
		loadSession()
	}

	loadWordlists()

	if config.Rate > 0 {
		rateLimiter = time.NewTicker(time.Duration(float64(time.Second) / float64(config.Rate))).C
	}

	strippedURL := strings.TrimPrefix(strings.TrimPrefix(config.URL, "https://"), "http://")
	if config.Mode == "vhost" || config.Mode == "dns" {
		parts := strings.Split(strippedURL, ".")
		if len(parts) > 1 {
			for i, p := range parts {
				if strings.Contains(p, "FUZZ") && i+1 < len(parts) {
					baseDomain = strings.Join(parts[i+1:], ".")
					break
				}
			}
		}
		if baseDomain == "" {
			baseDomain = strippedURL
		}
		if idx := strings.Index(baseDomain, "/"); idx != -1 {
			baseDomain = baseDomain[:idx]
		}
		if idx := strings.Index(baseDomain, "?"); idx != -1 {
			baseDomain = baseDomain[:idx]
		}
	}

	homeDir, _ := os.UserHomeDir()
	sessionDir := filepath.Join(homeDir, ".local", "share", "fux", "sessions")
	os.MkdirAll(sessionDir, 0755)
	hostForSession := strippedURL
	if parsedURL, err := url.Parse(config.URL); err == nil && parsedURL.Host != "" {
		hostForSession = parsedURL.Host
	}
	if hostForSession == "" {
		hostForSession = "unknown"
	}
	sessionPath = filepath.Join(sessionDir, strings.Replace(hostForSession, ":", "_", -1)+".json")

	// Exportación
	if config.Output != "" {
		var err error
		outputFile, err = os.OpenFile(config.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal("Error creando archivo de salida:", err)
		}
		defer outputFile.Close()
		if strings.HasSuffix(config.Output, ".csv") {
			csvWriter = csv.NewWriter(outputFile)
			defer csvWriter.Flush()
			csvWriter.Write([]string{"URL", "Status", "Size", "Words", "Lines", "Payloads", "Title", "IP", "Latency(ms)"})
		}
	}

	// Proxies
	if config.ProxyList != "" {
		loadProxies()
	}

	// Cliente HTTP/DNS
	transport := createCustomTransport()
	client = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if config.FollowRedirects {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			}
			return http.ErrUseLastResponse
		},
	}

	if !config.Silent && !config.OutputJson {
		printBanner()
		fmt.Print(styleInfo.Render(fmt.Sprintf("[*] Modo: %s | Objetivo: %s | Hilos: %d | T.Respuesta: %ds", config.Mode, config.URL, config.Threads, config.Timeout)) + "\n")
	}

	// Comprobar comodín DNS (Wildcard)
	if config.Mode == "dns" {
		checkDNSWildcard()
	}

	// Auto-Calibración (solo para web modes)
	if config.AutoCalibrate && config.Mode != "dns" {
		performAutoCalibration()
	}

	// Ctrl+C Captura
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if !config.Silent && !config.OutputJson {
			consoleMu.Lock()
			if progressActive {
				fmt.Print(clearLine)
			}
			fmt.Println(styleError.Render("\n[!] Interrumpido. Guardando sesión..."))
			consoleMu.Unlock()
		}
		saveSession()
		os.Exit(0)
	}()

	startTime = time.Now()
	runFuzzer()
}

// --- DESACTIVAR COLORES ---
func disableColors() {
	styleBanner = lipgloss.NewStyle()
	styleSuccess = lipgloss.NewStyle()
	styleWarning = lipgloss.NewStyle()
	styleInfo = lipgloss.NewStyle()
	styleDim = lipgloss.NewStyle()
	styleError = lipgloss.NewStyle()
	styleTime = lipgloss.NewStyle()
	styleIP = lipgloss.NewStyle()
	styleLatency = lipgloss.NewStyle()
	styleSize = lipgloss.NewStyle()
	styleWords = lipgloss.NewStyle()
	styleLines = lipgloss.NewStyle()
	styleTitle = lipgloss.NewStyle()
	styleCrit = lipgloss.NewStyle()
	styleTakeover = lipgloss.NewStyle()
	styleProgress = lipgloss.NewStyle()
}

// --- PARSEO DE FILTROS ---
func parseFilters() {
	if config.MatchStatus != "all" && config.MatchStatus != "" {
		for _, s := range strings.Split(config.MatchStatus, ",") {
			s = strings.TrimSpace(s)
			if code, err := strconv.Atoi(s); err == nil {
				matchStatusMap[code] = true
			}
		}
	}
	if config.FilterStatus != "" {
		for _, s := range strings.Split(config.FilterStatus, ",") {
			s = strings.TrimSpace(s)
			if code, err := strconv.Atoi(s); err == nil {
				filterStatusMap[code] = true
			}
		}
	}

	if config.FilterRegex != "" {
		var err error
		filterRegComp, err = regexp.Compile(config.FilterRegex)
		if err != nil {
			log.Fatalf("Expresión regular de filtro (-fr) inválida: %v", err)
		}
	}
	if config.MatchRegex != "" {
		var err error
		matchRegComp, err = regexp.Compile(config.MatchRegex)
		if err != nil {
			log.Fatalf("Expresión regular de match (-mr) inválida: %v", err)
		}
	}
}

// --- CALIBRACIÓN Y SESIONES Y PROXIES ---
func loadWordlists() {
	if len(config.Wordlists) == 0 {
		return
	}
	// Solo cargamos en memoria a partir de la segunda wordlist
	for i := 1; i < len(config.Wordlists); i++ {
		wl := config.Wordlists[i]
		var words []string
		if strings.HasPrefix(wl, "range:") {
			parts := strings.TrimPrefix(wl, "range:")
			bounds := strings.Split(parts, "-")
			if len(bounds) == 2 {
				start, _ := strconv.Atoi(bounds[0])
				end, _ := strconv.Atoi(bounds[1])
				for i := start; i <= end; i++ {
					words = append(words, strconv.Itoa(i))
				}
			}
		} else {
			f, err := os.Open(wl)
			if err != nil {
				log.Fatalf("No se pudo abrir wordlist %s: %v", wl, err)
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				words = append(words, scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				log.Fatalf("Error leyendo wordlist %s: %v", wl, err)
			}
			f.Close()
		}
		loadedWordlists = append(loadedWordlists, words)
	}
}

func loadProxies() {
	f, err := os.Open(config.ProxyList)
	if err != nil {
		log.Fatalf("No se pudo abrir proxy list: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if !strings.HasPrefix(line, "http") && !strings.HasPrefix(line, "socks") {
				line = "http://" + line
			}
			proxies = append(proxies, line)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error leyendo lista de proxies: %v", err)
	}
	if !config.Silent {
		fmt.Println(styleInfo.Render(fmt.Sprintf("[*] Cargados %d proxies", len(proxies))))
	}
}

func getNextProxy(_ *http.Request) (*url.URL, error) {
	if len(proxies) == 0 {
		return nil, nil
	}
	idx := proxyIndex.Add(1) % uint64(len(proxies))
	return url.Parse(proxies[idx])
}

func performAutoCalibration() {
	if !config.Silent {
		fmt.Println(styleDim.Render("[*] Iniciando Auto-Calibración (WAF/404s/200s anómalos)..."))
	}
	for i := 0; i < 5; i++ {
		randomPath := fmt.Sprintf("%016x", rand.Int63())
		payloads := map[string]string{"FUZZ": randomPath}
		res, _ := executeRequest(config.URL, payloads, false)

		calibMu.Lock()
		calibData.Statuses[res.Status] = true
		calibData.Sizes[res.Size] = true
		calibData.Words[res.Words] = true
		calibData.Lines[res.Lines] = true
		calibMu.Unlock()
	}
	if !config.Silent {
		fmt.Print(styleDim.Render(fmt.Sprintf("[-] Calibrado: %d tamaños, %d palabras, %d lineas filtrados por defecto\n", len(calibData.Sizes), len(calibData.Words), len(calibData.Lines))))
	}
}

func saveSession() {
	sess := Session{
		Config:    config,
		Timestamp: time.Now().Format(time.RFC3339),
		Index:     completedReq.Load(), // Índice global
	}
	data, _ := json.MarshalIndent(sess, "", "  ")
	os.WriteFile(sessionPath, data, 0644)
	if !config.Silent {
		fmt.Println(styleSuccess.Render("[+] Sesión guardada en " + sessionPath))
	}
}

func loadSession() {
	data, err := os.ReadFile(config.Resume)
	if err != nil {
		log.Fatalf("Error leyendo sesión: %v", err)
	}
	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		log.Fatalf("Sesión corrupta: %v", err)
	}

	// Mantener opciones manuales si se pasaron, sino usar la de sesion
	if len(config.Wordlists) == 0 {
		config.Wordlists = sess.Config.Wordlists
	}
	if config.URL == "" {
		config.URL = sess.Config.URL
	}
	resumeIndex = sess.Index
	if !config.Silent {
		fmt.Println(styleSuccess.Render(fmt.Sprintf("[+] Reanudando sesión en índice %d", resumeIndex)))
	}
}

// --- GENERADOR DE PAYLOADS (CLUSTER BOMB / SNIPER) ---

func getPayloadsCount() int64 {
	if len(config.Wordlists) == 0 {
		return 1
	}
	mainWl := config.Wordlists[0]
	var mainCount int64 = 0

	if strings.HasPrefix(mainWl, "range:") {
		parts := strings.TrimPrefix(mainWl, "range:")
		bounds := strings.Split(parts, "-")
		if len(bounds) == 2 {
			start, _ := strconv.ParseInt(bounds[0], 10, 64)
			end, _ := strconv.ParseInt(bounds[1], 10, 64)
			if end >= start {
				mainCount = end - start + 1
			}
		}
	} else {
		info, err := os.Stat(mainWl)
		if err == nil {
			size := info.Size()
			// Si es menor a 50MB, contamos exactamente rápido
			if size < 50*1024*1024 {
				f, err := os.Open(mainWl)
				if err == nil {
					scanner := bufio.NewScanner(f)
					for scanner.Scan() {
						mainCount++
					}
					if err := scanner.Err(); err != nil {
						log.Printf("[!] Error contando líneas de wordlist principal: %v", err)
					}
					f.Close()
				}
			} else {
				// Para archivos masivos estimamos basándonos en un tamaño de línea promedio de 12 bytes
				mainCount = size / 12
				if mainCount <= 0 {
					mainCount = 1
				}
			}
		}
	}

	if mainCount == 0 {
		mainCount = 1
	}

	var total int64 = mainCount
	for _, words := range loadedWordlists {
		total *= int64(len(words))
	}

	exts := 1
	if config.Extensions != "" {
		exts = len(strings.Split(config.Extensions, ",")) + 1
	}
	return total * int64(exts)
}

func generatePayloads(resumeIdx int64) <-chan RequestTask {
	out := make(chan RequestTask, 1000)

	go func() {
		defer close(out)

		exts := []string{""}
		if config.Extensions != "" {
			for _, e := range strings.Split(config.Extensions, ",") {
				exts = append(exts, "."+strings.TrimPrefix(e, "."))
			}
		}

		if len(config.Wordlists) == 0 {
			// Si no hay wordlists, emitir payload vacío una sola vez
			for _, ext := range exts {
				out <- RequestTask{Payloads: map[string]string{"FUZZ": ext}, TargetURL: config.URL, Depth: 0}
			}
			return
		}

		mainWl := config.Wordlists[0]
		keys := []string{"FUZZ", "FUZ2Z", "FUZ3Z", "FUZ4Z"}

		var currentIdx int64 = 0

		// Función auxiliar para emitir combinaciones con las wordlists secundarias cargadas en memoria
		emitCombinations := func(mainWord string) {
			if len(loadedWordlists) == 0 {
				for _, ext := range exts {
					if currentIdx >= resumeIdx {
						cleanV := mainWord
						if strings.HasSuffix(cleanV, ".") && strings.HasPrefix(ext, ".") {
							cleanV = strings.TrimSuffix(cleanV, ".")
						}
						out <- RequestTask{
							Payloads:  map[string]string{"FUZZ": cleanV + ext},
							TargetURL: config.URL,
							Depth:     0,
						}
					}
					currentIdx++
				}
				return
			}

			// Producto cartesiano de wordlists secundarias
			var generateSubs func(depth int, currentPayloads map[string]string)
			generateSubs = func(depth int, currentPayloads map[string]string) {
				if depth == len(loadedWordlists) {
					for _, ext := range exts {
						if currentIdx >= resumeIdx {
							payloadsCopy := make(map[string]string)
							for k, v := range currentPayloads {
								if k == "FUZZ" && ext != "" {
									cleanV := v
									if strings.HasSuffix(cleanV, ".") && strings.HasPrefix(ext, ".") {
										cleanV = strings.TrimSuffix(cleanV, ".")
									}
									payloadsCopy[k] = cleanV + ext
								} else {
									payloadsCopy[k] = v
								}
							}
							out <- RequestTask{Payloads: payloadsCopy, TargetURL: config.URL, Depth: 0}
						}
						currentIdx++
					}
					return
				}

				key := keys[depth+1] // depth + 1 porque depth 0 es el mainWord (FUZZ)
				for _, word := range loadedWordlists[depth] {
					currentPayloads[key] = word
					generateSubs(depth+1, currentPayloads)
				}
			}

			generateSubs(0, map[string]string{"FUZZ": mainWord})
		}

		// Leer wordlist principal (streaming)
		if strings.HasPrefix(mainWl, "range:") {
			parts := strings.TrimPrefix(mainWl, "range:")
			bounds := strings.Split(parts, "-")
			if len(bounds) == 2 {
				start, _ := strconv.Atoi(bounds[0])
				end, _ := strconv.Atoi(bounds[1])
				for i := start; i <= end; i++ {
					emitCombinations(strconv.Itoa(i))
				}
			}
		} else {
			f, err := os.Open(mainWl)
			if err != nil {
				log.Fatalf("No se pudo abrir wordlist %s: %v", mainWl, err)
			}
			defer f.Close()

			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				emitCombinations(scanner.Text())
			}
			if err := scanner.Err(); err != nil {
				log.Printf("[!] Error leyendo en streaming la wordlist: %v", err)
			}
		}
	}()
	return out
}

// --- MOTOR PRINCIPAL ---
func runFuzzer() {
	totalPayloads = getPayloadsCount()

	payloadChan := generatePayloads(resumeIndex)
	resultsChan = make(chan Result, config.Threads*4)
	recTasks = make(chan RecTask, 5000)

	// Procesador de resultados
	var wgWriter sync.WaitGroup
	wgWriter.Add(1)
	go resultProcessor(&wgWriter)

	// Barra de progreso interactiva
	progressDone := make(chan struct{})
	if !config.Silent && !config.OutputJson {
		go progressBar(progressDone)
	}

	// Pool de workers principales
	var wg sync.WaitGroup
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go worker(payloadChan, &wg)
	}

	// Sniper (Recursividad) en background
	sniperDone := make(chan struct{})
	go recursiveSniper(sniperDone)

	// Esperar workers principales
	wg.Wait()
	close(recTasks)

	<-sniperDone
	close(resultsChan)
	wgWriter.Wait()

	close(progressDone)
	if !config.Silent && !config.OutputJson {
		consoleMu.Lock()
		progressActive = false
		fmt.Print(clearLine)

		elapsed := time.Since(startTime)
		reqSec := float64(completedReq.Load()) / elapsed.Seconds()
		fmt.Println(styleSuccess.Render("\n[+] Fuzzing completado."))
		fmt.Print(styleDim.Render(fmt.Sprintf("Peticiones Totales: %d | Tiempo: %s | Tasa Promedio: %.0f reqs/s\n", completedReq.Load(), elapsed.Round(time.Second), reqSec)))
		consoleMu.Unlock()
	}

	if completedReq.Load() > 0 {
		os.Remove(sessionPath) // Limpiar sesión solo si se avanzó algo
	}
}

func drawProgressBarInternal() {
	if config.Silent || config.OutputJson || !progressActive {
		return
	}
	current := completedReq.Load()
	elapsed := time.Since(startTime)
	rate := float64(current) / elapsed.Seconds()

	pct := float64(0)
	if totalPayloads > 0 {
		pct = float64(current) / float64(totalPayloads) * 100
	}

	etaStr := "N/A"
	if rate > 0 && totalPayloads > current {
		etaSecs := float64(totalPayloads-current) / rate
		etaStr = (time.Duration(etaSecs) * time.Second).String()
	}

	// Render bar [======>    ]
	barLen := 20
	filled := int(pct / 100 * float64(barLen))
	if filled < 0 {
		filled = 0
	}
	if filled > barLen {
		filled = barLen
	}
	bar := strings.Repeat("=", filled)
	if filled < barLen {
		bar += ">" + strings.Repeat(" ", barLen-filled-1)
	}

	fmt.Printf("%s%s [%s] %d/%d reqs (%.1f%%) | %.0f reqs/s | ETA: %s",
		clearLine,
		styleProgress.Render("Progreso:"),
		styleDim.Render(bar),
		current, totalPayloads, pct, rate, etaStr)
}

func progressBar(done chan struct{}) {
	consoleMu.Lock()
	progressActive = true
	consoleMu.Unlock()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			consoleMu.Lock()
			drawProgressBarInternal()
			consoleMu.Unlock()
		}
	}
}

// --- RECURSIVIDAD ---
func recursiveSniper(done chan struct{}) {
	var recWg sync.WaitGroup
	// Pool de workers interno para recursividad para evitar deadlocks
	recWorkerChan := make(chan RequestTask, 1000)

	// Iniciar pool de workers recursivos (reutilizan la lógica)
	numRecWorkers := config.Threads / 2
	if numRecWorkers < 5 {
		numRecWorkers = 5
	}

	for i := 0; i < numRecWorkers; i++ {
		recWg.Add(1)
		go worker(recWorkerChan, &recWg)
	}

	var genWg sync.WaitGroup

	for task := range recTasks {
		if config.MaxDepth > 0 && task.Depth > config.MaxDepth {
			continue
		}
		if isDeadEnd(task.BaseURL) {
			continue
		}

		if !config.Silent && !config.OutputJson {
			consoleMu.Lock()
			if progressActive {
				fmt.Print(clearLine)
			}
			fmt.Println(styleWarning.Render(fmt.Sprintf("\n[▸] Recursividad (Prof %d): %s", task.Depth, task.BaseURL)))
			if progressActive {
				drawProgressBarInternal()
			}
			consoleMu.Unlock()
		}

		// Generar wordlist base de forma asíncrona para no bloquear el bucle de recTasks
		genWg.Add(1)
		go func(t RecTask) {
			defer genWg.Done()
			basePayloads := generatePayloads(0)
			for bp := range basePayloads {
				bp.TargetURL = t.BaseURL
				bp.Depth = t.Depth
				recWorkerChan <- bp
			}
		}(task)
	}

	genWg.Wait()
	close(recWorkerChan)
	recWg.Wait()
	close(done)
}

// --- WORKER ---
func worker(tasks <-chan RequestTask, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range tasks {
		if rateLimiter != nil {
			<-rateLimiter
		}

		totalReq.Add(1)

		res := processTask(task, false)
		if res == nil {
			completedReq.Add(1)
			continue // Err fatal continuo
		}

		if res.Status >= 200 && res.Status < 300 {
			if fuzzVal, ok := res.Payloads["FUZZ"]; ok {
				for _, cf := range criticalFiles {
					if strings.Contains(fuzzVal, cf) {
						res.IsCritical = true
						break
					}
				}
			}
		}

		if config.Mode == "vhost" || config.Mode == "dns" {
			domain := res.URL
			if config.Mode == "vhost" {
				domain = res.Payloads["FUZZ"] + "." + baseDomain
			}
			checkTakeover(res, domain)
		}

		// Filtros avanzados
		if shouldDiscard(res) {
			if config.Verbose {
				res.Filtered = true
				resultsChan <- *res
			}
			completedReq.Add(1)
			continue
		}

		resultsChan <- *res
		completedReq.Add(1)
	}
}

func processTask(task RequestTask, isMutated bool) *Result {
	var res Result
	var err error
	var attempt int

	for attempt = 0; attempt <= config.Retries; attempt++ {
		if config.Mode == "dns" {
			res, err = executeDNS(task.TargetURL, task.Payloads)
		} else {
			res, err = executeRequest(task.TargetURL, task.Payloads, isMutated)
		}

		if err == nil {
			break
		}
		if attempt < config.Retries {
			time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
		}
	}

	if err != nil {
		errCount := errorCount.Add(1)
		if errCount == 50 && totalReq.Load() < 100 {
			if !config.Silent {
				consoleMu.Lock()
				if progressActive {
					fmt.Print(clearLine)
				}
				fmt.Println(styleError.Render("\n[!] Advertencia: Muchos errores de red. Verifica conexión/target."))
				if progressActive {
					drawProgressBarInternal()
				}
				consoleMu.Unlock()
			}
		}
		return nil
	}
	errorCount.Store(0)

	if res.Status == 403 && config.SmartEncode && !isMutated {
		mutatedURL := mutatePayload(task.TargetURL, task.Payloads["FUZZ"])
		task.TargetURL = mutatedURL
		mutatedRes := processTask(task, true)
		if mutatedRes != nil && mutatedRes.Status != 403 {
			return mutatedRes
		}
	}

	res.Depth = task.Depth
	return &res
}

// --- EJECUCIÓN REQUEST ---
func executeRequest(targetTemplate string, payloads map[string]string, isMutated bool) (Result, error) {
	finalURL := targetTemplate
	for k, v := range payloads {
		escaped := url.PathEscape(v)
		escaped = strings.Replace(escaped, "%2F", "/", -1)
		finalURL = strings.Replace(finalURL, k, escaped, -1)
	}

	if !strings.HasPrefix(finalURL, "http") {
		finalURL = "https://" + finalURL
	}

	var bodyReader io.Reader
	reqBodyStr := config.Data
	if reqBodyStr != "" {
		for k, v := range payloads {
			reqBodyStr = strings.Replace(reqBodyStr, k, url.QueryEscape(v), -1)
		}
		bodyReader = strings.NewReader(reqBodyStr)
	}

	req, err := http.NewRequest(config.Method, finalURL, bodyReader)
	if err != nil {
		return Result{}, err
	}

	hasCustomCT := false
	hasCustomUA := false
	for _, h := range config.Headers {
		hReplaced := h
		for k, v := range payloads {
			hReplaced = strings.Replace(hReplaced, k, v, -1)
		}
		parts := strings.SplitN(hReplaced, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			if strings.ToLower(key) == "host" {
				req.Host = val
			} else {
				req.Header.Set(key, val)
			}

			if strings.ToLower(key) == "user-agent" {
				hasCustomUA = true
			}
			if strings.ToLower(key) == "content-type" {
				hasCustomCT = true
			}
		}
	}

	if config.Mode == "vhost" {
		vhost := payloads["FUZZ"] + "." + baseDomain
		req.Host = vhost
	}

	if !hasCustomUA {
		req.Header.Set("User-Agent", getRandomUA())
	}
	if !hasCustomCT && config.Data != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if isMutated {
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")
		req.Header.Set("Client-IP", "127.0.0.1")
	}

	var remoteAddr string
	var start time.Time
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) { remoteAddr = connInfo.Conn.RemoteAddr().String() },
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start = time.Now()

	resp, err := client.Do(req)
	if err != nil && !isMutated && strings.HasPrefix(finalURL, "https://") {
		errStr := err.Error()
		if !strings.Contains(errStr, "no such host") && !strings.Contains(errStr, "context deadline exceeded") {
			httpURL := strings.Replace(finalURL, "https://", "http://", 1)
			req.URL, _ = url.Parse(httpURL)
			if reqBodyStr != "" {
				req.Body = io.NopCloser(strings.NewReader(reqBodyStr))
			}
			start = time.Now()
			resp, err = client.Do(req)
		}
	}
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	latency := time.Since(start).Milliseconds()

	ip := remoteAddr
	if strings.Contains(ip, ":") {
		ip, _, _ = net.SplitHostPort(ip)
	}

	ct := resp.Header.Get("Content-Type")
	isDir := (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308) && strings.HasSuffix(resp.Header.Get("Location"), "/")

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	io.Copy(io.Discard, resp.Body)

	size := int64(len(bodyBytes))
	words := len(bytes.Fields(bodyBytes))
	lines := bytes.Count(bodyBytes, []byte("\n"))

	title := extractTitleFromBytes(bodyBytes)

	return Result{
		Payloads:    payloads,
		Status:      resp.StatusCode,
		Size:        size,
		Words:       words,
		Lines:       lines,
		URL:         finalURL,
		IsDir:       isDir,
		ContentType: ct,
		IP:          ip,
		Latency:     latency,
		Timestamp:   time.Now().Format("15:04:05"),
		Title:       title,
		Body:        bodyBytes,
	}, nil
}

// --- DNS MODE ---
func executeDNS(targetTemplate string, payloads map[string]string) (Result, error) {
	finalDomain := targetTemplate
	for k, v := range payloads {
		finalDomain = strings.Replace(finalDomain, k, v, -1)
	}
	finalDomain = strings.TrimPrefix(strings.TrimPrefix(finalDomain, "https://"), "http://")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.Timeout)*time.Second)
	defer cancel()

	start := time.Now()
	resResolver := globalResolver
	if resResolver == nil {
		resResolver = net.DefaultResolver
	}

	ips, err := resResolver.LookupIPAddr(ctx, finalDomain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && (dnsErr.IsNotFound || strings.Contains(dnsErr.Error(), "no such host")) {
			return Result{
				Payloads:  payloads,
				Status:    404,
				Size:      0,
				Words:     0,
				Lines:     0,
				URL:       finalDomain,
				IP:        "",
				Latency:   time.Since(start).Milliseconds(),
				Timestamp: time.Now().Format("15:04:05"),
			}, nil
		}
		return Result{}, err
	}
	latency := time.Since(start).Milliseconds()

	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.IP.String())
	}
	ipJoined := strings.Join(ipStrs, ", ")

	return Result{
		Payloads:  payloads,
		Status:    200, // Simular OK para DNS
		Size:      0,
		Words:     0,
		Lines:     0,
		URL:       finalDomain,
		IP:        ipJoined,
		Latency:   latency,
		Timestamp: time.Now().Format("15:04:05"),
	}, nil
}

// --- FILTROS Y REGLAS ---
func shouldDiscard(res *Result) bool {
	if config.Mode == "dns" && res.IP == "" && !res.PotTakeover {
		return true
	}

	if len(matchStatusMap) > 0 && !matchStatusMap[res.Status] {
		return true
	}
	if filterStatusMap[res.Status] {
		return true
	}

	if config.AutoCalibrate && config.Mode != "dns" {
		calibMu.Lock()
		if calibData.Sizes[res.Size] || calibData.Words[res.Words] || calibData.Lines[res.Lines] {
			if res.Status != 200 || (res.Status == 200 && calibData.Statuses[200]) {
				calibMu.Unlock()
				return true
			}
		}
		calibMu.Unlock()
	}

	if config.Mode != "dns" {
		if config.FilterText != "" && bytes.Contains(res.Body, []byte(config.FilterText)) {
			return true
		}
		if config.MatchText != "" && !bytes.Contains(res.Body, []byte(config.MatchText)) {
			return true
		}
		if filterRegComp != nil && filterRegComp.Match(res.Body) {
			return true
		}
		if matchRegComp != nil && !matchRegComp.Match(res.Body) {
			return true
		}
	}

	if config.FilterSize != "" && checkRange(int64(res.Size), config.FilterSize) {
		return true
	}
	if config.MatchSize != "" && !checkRange(int64(res.Size), config.MatchSize) {
		return true
	}

	if config.FilterWords != "" && checkRange(int64(res.Words), config.FilterWords) {
		return true
	}
	if config.MatchWords != "" && !checkRange(int64(res.Words), config.MatchWords) {
		return true
	}

	if config.FilterLines != "" && checkRange(int64(res.Lines), config.FilterLines) {
		return true
	}
	if config.MatchLines != "" && !checkRange(int64(res.Lines), config.MatchLines) {
		return true
	}

	return false
}

func checkRange(val int64, pattern string) bool {
	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		min, _ := strconv.ParseInt(parts[0], 10, 64)
		max, _ := strconv.ParseInt(parts[1], 10, 64)
		return val >= min && val <= max
	}
	target, _ := strconv.ParseInt(pattern, 10, 64)
	return val == target
}

// --- RESULT PROCESSOR ---
func safeSendRecTask(task RecTask) {
	defer func() {
		_ = recover()
	}()
	recTasks <- task
}

func resultProcessor(wg *sync.WaitGroup) {
	defer wg.Done()
	for res := range resultsChan {
		// Auto recursión solo en DIR mode
		if res.IsDir && config.Recursion && config.Data == "" && !res.Filtered {
			updateDirStats(res.URL, res.Size)
			safeSendRecTask(RecTask{BaseURL: res.URL + "FUZZ", Depth: res.Depth + 1})
		}

		if config.OutputJson {
			data, _ := json.Marshal(res)
			fmt.Println(string(data))
		} else {
			printResult(res)
		}

		if !res.Filtered {
			exportResult(res)
		}
	}
}

func exportResult(res Result) {
	if outputFile == nil {
		return
	}
	fileMu.Lock()
	defer fileMu.Unlock()

	payloadsStr := ""
	for k, v := range res.Payloads {
		payloadsStr += fmt.Sprintf("%s=%s;", k, v)
	}

	if strings.HasSuffix(config.Output, ".csv") {
		csvWriter.Write([]string{
			res.URL,
			strconv.Itoa(res.Status),
			strconv.FormatInt(res.Size, 10),
			strconv.Itoa(res.Words),
			strconv.Itoa(res.Lines),
			payloadsStr,
			res.Title,
			res.IP,
			strconv.FormatInt(res.Latency, 10),
		})
		csvWriter.Flush()
	} else if !config.OutputJson { // Si OutputJson ya se imprimió stdout en formato json
		data, _ := json.Marshal(res)
		outputFile.Write(append(data, '\n'))
	}
}

func printResult(res Result) {
	if config.Silent {
		consoleMu.Lock()
		fmt.Println(res.URL)
		consoleMu.Unlock()
		return
	}

	var outBuf strings.Builder

	if res.Filtered {
		outBuf.WriteString(fmt.Sprintf("[FILTRADO] %s\n", res.URL))
	} else {
		timeStr := styleTime.Render(res.Timestamp)
		statusStr := strconv.Itoa(res.Status)
		styleStatus := lipgloss.NewStyle().Bold(true)
		switch {
		case res.Status >= 200 && res.Status < 300:
			styleStatus = styleStatus.Foreground(lipgloss.Color("#50FA7B"))
		case res.Status >= 300 && res.Status < 400:
			styleStatus = styleStatus.Foreground(lipgloss.Color("#8BE9FD"))
		case res.Status >= 400 && res.Status < 500:
			styleStatus = styleStatus.Foreground(lipgloss.Color("#FFB86C"))
		default:
			styleStatus = styleStatus.Foreground(lipgloss.Color("#FF5555"))
		}

		ipStr := styleIP.Render(res.IP)
		latStr := styleLatency.Render(fmt.Sprintf("%dms", res.Latency))
		sizeStr := styleSize.Render(fmt.Sprintf("%db", res.Size))
		wordsStr := styleWords.Render(fmt.Sprintf("%dw", res.Words))
		linesStr := styleLines.Render(fmt.Sprintf("%dl", res.Lines))
		titleStr := styleTitle.Render(res.Title)

		// Formatear payloads
		var p []string
		for k, v := range res.Payloads {
			p = append(p, fmt.Sprintf("%s:%s", k, v))
		}
		payloadStr := styleDim.Render(fmt.Sprintf("[%s]", strings.Join(p, " ")))

		urlStr := styleSuccess.Render(res.URL)

		tags := ""
		if res.IsCritical {
			urlStr = styleCrit.Render(res.URL)
			tags += styleCrit.Render(" [CRÍTICO]")
		}
		if res.PotTakeover {
			urlStr = styleTakeover.Render(res.URL)
			tags += styleTakeover.Render(fmt.Sprintf(" [TAKEOVER POSIBLE: %s]", res.CNAME))
		}

		// [TIME] [STATUS] [IP] [SIZE,WORDS,LINES] [LATENCY] URL TITLE [PAYLOADS]
		outBuf.WriteString(fmt.Sprintf("[%s] [%s] [%s] [%s,%s,%s] [%s] %s %s %s%s\n",
			timeStr, styleStatus.Render(statusStr), ipStr, sizeStr, wordsStr, linesStr, latStr, urlStr, titleStr, payloadStr, tags))
	}

	consoleMu.Lock()
	if progressActive {
		fmt.Print(clearLine)
	}
	fmt.Print(outBuf.String())
	if progressActive {
		drawProgressBarInternal()
	}
	consoleMu.Unlock()
}

// --- UTILIDADES ---
func mutatePayload(targetURL string, payload string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	bypassSuffixes := []string{"/", "/.", "/..;/", "/%2e/", "/..%2f"}
	u.Path = strings.TrimSuffix(u.Path, "/") + bypassSuffixes[rand.Intn(len(bypassSuffixes))]
	return u.String()
}

func extractTitleFromBytes(bodyBytes []byte) string {
	matches := titleRegex.FindStringSubmatch(string(bodyBytes))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func getPathFromURL(rawURL string) string {
	u, _ := url.Parse(rawURL)
	return u.Path
}

func initUserAgents() {
	userAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0",
		"fux-scanner/2.0",
	}
}

func getRandomUA() string {
	if config.RandomAgent {
		return userAgents[rand.Intn(len(userAgents))]
	}
	return userAgents[0]
}

func createCustomTransport() *http.Transport {
	if config.Resolver != "" {
		globalResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: time.Duration(config.Timeout) * time.Second}).DialContext(ctx, "udp", fmt.Sprintf("%s:53", config.Resolver))
			},
		}
	}

	dialer := &net.Dialer{Timeout: time.Duration(config.Timeout) * time.Second, Resolver: globalResolver}

	// Proxy support (HTTP/SOCKS5)
	var proxyFunc func(*http.Request) (*url.URL, error)
	var dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)
	var isSocks bool

	if len(proxies) > 0 {
		proxyFunc = getNextProxy
		// Si usamos SOCKS5
		firstProxy := proxies[0]
		if strings.HasPrefix(firstProxy, "socks5://") {
			dialerProxy, err := proxy.SOCKS5("tcp", strings.TrimPrefix(firstProxy, "socks5://"), nil, proxy.Direct)
			if err == nil {
				dialContextFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialerProxy.Dial(network, addr)
				}
				isSocks = true
			}
		}
	}

	if dialContextFunc == nil {
		dialContextFunc = dialer.DialContext
	}

	transport := &http.Transport{
		DialContext:         dialContextFunc,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        500,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false, // Mejorar velocidad
	}
	if proxyFunc != nil && !isSocks {
		transport.Proxy = proxyFunc
	}

	return transport
}

func updateDirStats(reqURL string, size int64) {
	path := getPathFromURL(reqURL)
	dirStatsMu.Lock()
	defer dirStatsMu.Unlock()
	if _, ok := dirStats[path]; !ok {
		dirStats[path] = make(map[int64]int)
	}
	dirStats[path][size]++
}

func isDeadEnd(baseURL string) bool {
	path := getPathFromURL(baseURL)
	dirStatsMu.Lock()
	defer dirStatsMu.Unlock()
	if sizes, ok := dirStats[path]; ok {
		for _, count := range sizes {
			if count > 30 {
				return true
			}
		}
	}
	return false
}

func checkTakeover(res *Result, domain string) {
	// Limpiar domain de puertos, rutas, esquemas
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")
	uStr := domain
	if !strings.HasPrefix(uStr, "http://") && !strings.HasPrefix(uStr, "https://") {
		uStr = "http://" + uStr
	}
	if u, err := url.Parse(uStr); err == nil {
		domain = u.Hostname()
	} else {
		if idx := strings.Index(domain, "/"); idx != -1 {
			domain = domain[:idx]
		}
		if idx := strings.Index(domain, ":"); idx != -1 {
			domain = domain[:idx]
		}
	}

	var cname string
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resResolver := globalResolver
	if resResolver == nil {
		resResolver = net.DefaultResolver
	}
	cname, err = resResolver.LookupCNAME(ctx, domain)

	if err == nil && cname != "" && cname != domain+"." {
		res.CNAME = cname
		for _, vuln := range takeoverCNAMEs {
			if strings.Contains(cname, vuln) {
				res.PotTakeover = true
				break
			}
		}
	}
}

func checkDNSWildcard() {
	if config.Mode != "dns" {
		return
	}
	randomSub := fmt.Sprintf("fux-wildcard-%016x.%s", rand.Int63(), baseDomain)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resResolver := globalResolver
	if resResolver == nil {
		resResolver = net.DefaultResolver
	}
	ips, err := resResolver.LookupIPAddr(ctx, randomSub)
	if err == nil && len(ips) > 0 {
		var ipStrs []string
		for _, ip := range ips {
			ipStrs = append(ipStrs, ip.IP.String())
		}
		joinedIPs := strings.Join(ipStrs, ", ")
		if !config.Silent {
			fmt.Println(styleWarning.Render(fmt.Sprintf("\n[!] Advertencia: Comodín DNS (Wildcard) detectado. %s resuelve a [%s].\n    Todos los subdominios inexistentes marcarán 200/OK. Se recomienda usar '-fc 404' o filtrar estas IPs.", randomSub, joinedIPs)))
		}
	}
}

// --- UI HELP ---
func printBanner() {
	banner := `
 ________ ___  ___     ___    ___ 
|\  _____\\  \|\  \   |\  \  /  /|
\ \  \__/\ \  \\\  \  \ \  \/  / /
 \ \   __\\ \  \\\  \  \ \    / / 
  \ \  \_| \ \  \\\  \  /     \/  
   \ \__\   \ \_______\/  /\   \  
    \|__|    \|_______/__/ /\ __\ 
                      |__|/ \|__| 

			 FUzzer-Xtreme (By RedSpyder Security)
    `
	fmt.Println(styleBanner.Render(banner))
}

func printHelp() {
	printBanner()
	helpText := `
Uso:
  fux -u https://target.com/FUZZ -w wordlist.txt [opciones]

Modos y Payload:
  -u string         URL Objetivo (Usa FUZZ, FUZ2Z para inyectar)
  -w string         Wordlist (múltiples permitidas: -w w1.txt -w w2.txt)
                    Soporta generadores: range:1-1000
  -mode string      Modo: dir (default), vhost, dns
  -t int            Hilos / Concurrencia (Default: 40)
  -x string         Extensiones separadas por coma (ej. php,asp)

Filtros y Matches (Soporta múltiples ej: 200,301):
  -mc string        Match status code (Default: 200,204,301,302,307,308,401,403,405,500)
  -fc string        Filter status code (Default: 404)
  -ms / -fs         Match / Filter por tamaño o rango (ej. 100-200)
  -mw / -fw         Match / Filter por cantidad de palabras
  -ml / -fl         Match / Filter por cantidad de líneas
  -mt / -ft         Match / Filter por string en body
  -mr / -fr         Match / Filter por regex en body

HTTP Request y Evasión:
  -X string         Método HTTP (Default: GET)
  -d string         Data body para POST/PUT (ej. "user=admin&pass=FUZZ")
  -H string         Header personalizado (-H "Cookie: a=1")
  -r string         DNS custom (ej. 8.8.8.8)
  -p string         Lista de proxies (http/socks5)
  -se               Smart Encode: Auto-bypass WAF en 403
  -ra               Random User-Agent
  -follow           Seguir redirecciones

Rendimiento y Control:
  -timeout int      Timeout por request en segs (Default: 10)
  -retries int      Reintentos automáticos en caso de error (Default: 0)
  -rate int         Rate Limit (req/s. 0 = ilimitado)
  -rec              Recursividad inteligente en carpetas
  -md int           Profundidad máxima recursividad (Default: 3)
  -ac               Auto-calibración de falsos positivos (404/200 anómalos)

Salida y UI:
  -o string         Exportar resultados a archivo (.json o .csv)
  -oj               Forzar salida estricta JSONL (apaga UI text)
  -v                Modo detallado (muestra requests filtrados)
  -silent           Modo silencioso (solo resultados, ideal pipes)
  -no-color         Desactiva colores
  -res string       Reanudar sesión guardada
`
	fmt.Println(helpText)
}
