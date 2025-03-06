package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sync"
)

type Leak struct {
	URL   string `json:"url"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

var (
	urlFlag  = flag.String("u", "", "URL única para processar")
	listFlag = flag.String("l", "", "Arquivo com lista de URLs para processar")
	outFile  = flag.String("o", "", "Arquivo de saída para salvar os resultados")
	format   = flag.String("format", "txt", "Formato de saída: txt ou json")
	
	regexMap = map[string]string{
		 // Chaves de API e Tokens
		 "Google API Key":                   `AIza[0-9A-Za-z-_]{35}`,
		 "Google Captcha Key":               `6L[0-9A-Za-z-_]{38}|6[0-9a-zA-Z_-]{39}`,
		 "Google OAuth Access Token":        `ya29\.[0-9A-Za-z\-_]+`,
		 "Amazon AWS Access Key ID":         `AKIA[0-9A-Z]{16}`,
		 "Amazon MWS Auth Token":            `amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
		 "Facebook Access Token":            `EAACEdEose0cBA[0-9A-Za-z]+`,
		 "Mailgun API Key":                  `key-[0-9a-zA-Z]{32}`,
		 "Twilio API Key":                   `SK[0-9a-fA-F]{32}`,
		 "Twilio Account SID":               `AC[a-zA-Z0-9_\-]{32}`,
		 "PayPal Braintree Access Token":    `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
		 "Square OAuth Secret":              `sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`,
		 "Stripe Standard API Key":          `sk_live_[0-9a-zA-Z]{24}`,
		 "Stripe Restricted API Key":        `rk_live_[0-9a-zA-Z]{24}`,
		 "GitHub Access Token":              `ghp_[0-9a-zA-Z]{36}`,
		 "Slack Token":                      `xox[baprs]-([0-9a-zA-Z]{10,48})?`,
		 "Heroku API Key":                   `heroku_[0-9a-zA-Z]{25,70}`,
		 "Dropbox API Key":                  `([a-z0-9]{15}|[a-z0-9]{16})`,
		 "Shopify Access Token":             `[0-9a-fA-F]{32}`,
		 "Azure Storage Account Key":        `(?:[a-zA-Z0-9+\/=]{88})`,
		 "Firebase Cloud Messaging Key":     `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
		 "JWT":                              `eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*$`,
 
		 // Chaves Privadas
		 "RSA Private Key":                  `-----BEGIN RSA PRIVATE KEY-----`,
		 "DSA Private Key":                  `-----BEGIN DSA PRIVATE KEY-----`,
		 "EC Private Key":                   `-----BEGIN EC PRIVATE KEY-----`,
		 "PGP Private Key Block":            `-----BEGIN PGP PRIVATE KEY BLOCK-----`,
 
		 // Senhas e Credenciais
		 "Generic Password":                 `(?i)(?:pass(?:word|phrase)|secret)(?:[\s:=]|%3A)(["']?[\w!@#$%^&*()]{8,}["']?)`,
		 "Email Address":                    `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`,
		 "AWS Secret Key":                   `(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]`,
 
		 // Outros
		 "AWS URL":                          `s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`,
		 "Authorization Basic":              `basic\s*[a-zA-Z0-9=:_\+\/-]+`,
		 "Authorization Bearer":             `bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+`,
		 "Authorization API":                `api[key|\s*]+[a-zA-Z0-9_\-]+`,
		 "Generic API Key":                  `[a-zA-Z0-9_-]{32,45}`,
	}
)

func main() {
	flag.Parse()
	var urls []string

	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	} else if *listFlag != "" {
		file, err := os.Open(*listFlag)
		if err != nil {
			fmt.Println("Erro ao abrir o arquivo:", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
	} else {
		info, _ := os.Stdin.Stat()
		if info.Mode()&os.ModeCharDevice == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				urls = append(urls, scanner.Text())
			}
		} else {
			fmt.Println("Nenhuma URL fornecida. Use -u, -l ou pipe.")
			return
		}
	}

	var wg sync.WaitGroup
	results := make(chan Leak, len(urls))

	for _, url := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			processURL(u, results)
		}(url)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	saveResults(results)
}

func processURL(url string, results chan<- Leak) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Erro ao acessar a URL:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Erro ao ler o conteúdo:", err)
		return
	}

	for name, pattern := range regexMap {
		regex := regexp.MustCompile(pattern)
		matches := regex.FindAllString(string(body), -1)
		for _, match := range matches {
			results <- Leak{URL: url, Type: name, Value: match}
		}
	}
}

func saveResults(results <-chan Leak) {
	var file *os.File
	var err error

	if *outFile != "" {
		file, err = os.Create(*outFile)
		if err != nil {
			fmt.Println("Erro ao criar arquivo de saída:", err)
			return
		}
		defer file.Close()
	}

	if *format == "json" {
		var leaks []Leak
		for result := range results {
			leaks = append(leaks, result)
		}
		output, _ := json.MarshalIndent(leaks, "", "  ")
		if file != nil {
			file.Write(output)
		} else {
			fmt.Println(string(output))
		}
	} else {
		writer := bufio.NewWriter(file)
		for result := range results {
			output := fmt.Sprintf("--------------------------\nURL: %s\nTOKEN: %s\nVALUE: %s\n", result.URL, result.Type, result.Value)
			if file != nil {
				writer.WriteString(output + "\n")
			} else {
				fmt.Print(output)
			}
		}
		if file != nil {
			writer.Flush()
		}
	}
}
