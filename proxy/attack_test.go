package proxy

import (
	"strings"
	"testing"
)

func TestTemplateEngineReconstruct(t *testing.T) {
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"X-Custom-Header": "prefix-§hdr§-suffix",
	}
	body := "user=§usr§&pass=§pwd§"
	targetURL := "http://example.com/api?debug=§dbg§"

	engine := NewTemplateEngine(targetURL, headers, body)

	if len(engine.Placeholders) != 4 {
		t.Fatalf("expected 4 placeholders, got %d", len(engine.Placeholders))
	}

	payloads := map[int]string{
		0: "1",      // dbg
		1: "header", // hdr
		2: "admin",  // usr
		3: "secret", // pwd
	}

	urlOut, headersOut, bodyOut := engine.Reconstruct(payloads, headers)

	if urlOut != "http://example.com/api?debug=1" {
		t.Errorf("unexpected URL: %s", urlOut)
	}

	if headersOut["X-Custom-Header"] != "prefix-header-suffix" {
		t.Errorf("unexpected header X-Custom-Header: %s", headersOut["X-Custom-Header"])
	}

	if bodyOut != "user=admin&pass=secret" {
		t.Errorf("unexpected body: %s", bodyOut)
	}
}

func TestInjectAutoMarkers(t *testing.T) {
	config := AttackConfig{
		TargetURL:    "http://example.com/login",
		UserField:    "username",
		PassField:    "password",
		OriginalBody: "username=testuser&password=testpass",
		Headers:      map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
	}

	InjectAutoMarkers(&config)

	if !strings.Contains(config.OriginalBody, "username=§testuser§") {
		t.Errorf("expected username=§testuser§, got: %s", config.OriginalBody)
	}
	if !strings.Contains(config.OriginalBody, "password=§testpass§") {
		t.Errorf("expected password=§testpass§, got: %s", config.OriginalBody)
	}
}

func TestGenerateJobsSniper(t *testing.T) {
	engine := NewTemplateEngine("http://example.com/login", nil, "user=§usr§&pass=§pwd§")
	payloads1 := []string{"p1", "p2"}
	payloads2 := []string{"s1", "s2"}

	jobsChan := make(chan attackJob, 10)
	cancelChan := make(chan bool)

	GenerateJobs(engine, payloads1, payloads2, "Sniper", jobsChan, cancelChan)
	close(jobsChan)

	var list []attackJob
	for j := range jobsChan {
		list = append(list, j)
	}

	if len(list) != 4 {
		t.Fatalf("expected 4 jobs for Sniper, got %d", len(list))
	}

	// Job 1 should replace marker 0 (usr) with p1, keeping marker 1 default (pwd)
	if list[0].payloadMap[0] != "p1" || list[0].payloadMap[1] != "" {
		t.Errorf("Job 1 payload incorrect: %v", list[0].payloadMap)
	}
	// Job 2 should replace marker 0 (usr) with p2
	if list[1].payloadMap[0] != "p2" {
		t.Errorf("Job 2 payload incorrect: %v", list[1].payloadMap)
	}
	// Job 3 should replace marker 1 (pwd) with p1
	if list[2].payloadMap[1] != "p1" {
		t.Errorf("Job 3 payload incorrect: %v", list[2].payloadMap)
	}
}
