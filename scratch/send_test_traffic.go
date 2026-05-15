package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func main() {
	// Proxy adresimiz (Proxy Inspector'ın dinlediği port)
	proxyURL, _ := url.Parse("http://127.0.0.1:3000")
	
	// İstekleri proxy üzerinden gönderecek HTTP istemcisi
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	fmt.Println("Trafiği Proxy üzerinden (127.0.0.1:3000) hedefe (127.0.0.1:8080) gönderiyorum...")
	
	// Gönderilecek form verisi (yanlış şifreyle bir giriş denemesi)
	data := url.Values{}
	data.Set("username", "admin")
	data.Set("password", "yanlissifre")

	req, err := http.NewRequest("POST", "http://127.0.0.1:8080/login", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Printf("İstek oluşturulamadı: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) TestScript/1.0")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Hata: Proxy açık değil olabilir mi? %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("İstek başarıyla gönderildi! Sunucudan gelen cevap kodu: %d\n", resp.StatusCode)
	fmt.Println("\n>>> ŞİMDİ PROXY INSPECTOR EKRANINA BAK <<<")
	fmt.Println("1. Listede 'POST http://127.0.0.1:8080/login' isteğini göreceksin.")
	fmt.Println("2. Yön tuşlarıyla o isteğin üzerine gel.")
	fmt.Println("3. 'A' (büyük A) tuşuna basarak doğrudan Brute Force menüsüne geç!")
}
