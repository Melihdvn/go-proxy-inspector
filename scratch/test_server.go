package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type IPStat struct {
	totalAttempts   int
	lastRequestTime time.Time
	reqInSecond     int
}

var (
	correctPassword string
	stats           = make(map[string]*IPStat)
	mu              sync.Mutex
)

func main() {
	fmt.Print("Test için geçerli şifreyi girin: ")
	fmt.Scanln(&correctPassword)
	fmt.Printf("Gerçekçi Korumalı Sunucu Başlatıldı. Şifre: '%s'\n", correctPassword)
	fmt.Println("Kural: Her IP saniyede max 5 istek atabilir ve toplam 50 hata yapabilir.")

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		// Gerçek IP veya Sahte IP'yi al
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}

		// IP İstatistiklerini Getir veya Oluştur
		stat, exists := stats[clientIP]
		if !exists {
			stat = &IPStat{}
			stats[clientIP] = stat
		}

		stat.totalAttempts++
		
		// 1. Rate Limit Kontrolü (IP Bazlı)
		now := time.Now()
		if now.Sub(stat.lastRequestTime) < time.Second {
			stat.reqInSecond++
		} else {
			stat.reqInSecond = 1
			stat.lastRequestTime = now
		}

		if stat.reqInSecond > 5 {
			fmt.Printf("[!] RATE LIMIT! IP: %s - Bu saniyedeki isteği: %d\n", clientIP, stat.reqInSecond)
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Çok fazla istek!"))
			return
		}

		// 2. IP Ban Kontrolü (IP Bazlı 50 deneme)
		if stat.totalAttempts > 50 {
			fmt.Printf("[X] IP ENGELLİ! IP: %s - Toplam Denemesi: %d\n", clientIP, stat.totalAttempts)
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Bu IP engellendi!"))
			return
		}

		// Verileri Oku
		var user, pass string
		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			body, _ := io.ReadAll(r.Body)
			var data map[string]string
			json.Unmarshal(body, &data)
			user = data["username"]
			pass = data["password"]
		} else {
			r.ParseForm()
			user = r.FormValue("username")
			pass = r.FormValue("password")
		}

		// Log Yaz
		ua := r.Header.Get("User-Agent")
		if len(ua) > 20 { ua = ua[:17] + "..." }
		fmt.Printf("IP: %-15s | UA: %-20s | Pass: %s\n", clientIP, ua, pass)

		if user == "admin" && pass == correctPassword {
			fmt.Println("--> !!! BAŞARILI !!!")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success", "token": "JWT-SECRET-999123", "role": "admin"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hatalı"))
	})

	http.ListenAndServe(":8080", nil)
}
