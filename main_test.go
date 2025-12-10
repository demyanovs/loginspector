package main

import (
	"os"
	"testing"
	"time"
)

// Test parseLine function
func TestParseLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantErr bool
		check   func(*LogEntry) bool
	}{
		{
			name:    "Valid line with Chrome",
			line:    `[u-0][08/Dec/2025:14:23:45 +0300] 0.123 0.456 200 192.168.1.1 example.com GET /api/users HTTP/1.1 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"`,
			wantErr: false,
			check: func(e *LogEntry) bool {
				expectedTime, _ := time.Parse("02/Jan/2006:15:04:05", "08/Dec/2025:14:23:45")
				return e.StatusCode == "200" &&
					e.IP == "192.168.1.1" &&
					e.Domain == "example.com" &&
					e.Hour == "14" &&
					e.Method == "GET" &&
					e.Path == "/api/users" &&
					e.Timestamp.Equal(expectedTime)
			},
		},
		{
			name:    "Valid line with POST",
			line:    `[u-0][10/Dec/2025:09:15:30 +0000] 0.050 0.100 201 10.0.0.5 api.example.com POST /data HTTP/2.0 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"`,
			wantErr: false,
			check: func(e *LogEntry) bool {
				return e.Method == "POST" && e.StatusCode == "201" && e.Hour == "09"
			},
		},
		{
			name:    "Invalid line format",
			line:    "This is not a valid log line",
			wantErr: true,
		},
		{
			name:    "Empty line",
			line:    "",
			wantErr: true,
		},
		{
			name:    "Line with 403 error",
			line:    `[u-0][08/Dec/2025:23:59:59 +0300] 0.010 0.020 403 192.168.1.100 example.com GET /admin HTTP/1.1 "Mozilla/5.0"`,
			wantErr: false,
			check: func(e *LogEntry) bool {
				return e.StatusCode == "403" && e.Hour == "23"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := parseLine(tt.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil && !tt.check(entry) {
				t.Errorf("parseLine() entry validation failed for %s", tt.name)
			}
		})
	}
}

// Test detectBrowser function
func TestDetectBrowser(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Chrome on Windows",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			want:      "Chrome",
		},
		{
			name:      "Firefox on macOS",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
			want:      "Firefox",
		},
		{
			name:      "Safari on macOS",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
			want:      "Safari",
		},
		{
			name:      "Edge on Windows",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
			want:      "Edge",
		},
		{
			name:      "Opera on Windows",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.203",
			want:      "Opera",
		},
		{
			name:      "Internet Explorer 11",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
			want:      "Internet Explorer",
		},
		{
			name:      "Unknown browser",
			userAgent: "SomeUnknownBrowser/1.0",
			want:      "Other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectBrowser(tt.userAgent); got != tt.want {
				t.Errorf("detectBrowser() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test detectDevice function
func TestDetectDevice(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Desktop Windows Chrome",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			want:      "Desktop",
		},
		{
			name:      "Mobile Android Chrome",
			userAgent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
			want:      "Mobile",
		},
		{
			name:      "iPhone (Mobile)",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
			want:      "Mobile",
		},
		{
			name:      "iPad (Tablet)",
			userAgent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			want:      "Tablet",
		},
		{
			name:      "Android Tablet",
			userAgent: "Mozilla/5.0 (Linux; Android 11; SM-T870) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36 Tablet",
			want:      "Tablet",
		},
		{
			name:      "Desktop macOS",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			want:      "Desktop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectDevice(tt.userAgent); got != tt.want {
				t.Errorf("detectDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test detectOS function
func TestDetectOS(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Windows 10",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			want:      "Windows",
		},
		{
			name:      "macOS",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			want:      "macOS",
		},
		{
			name:      "Android",
			userAgent: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Mobile Safari/537.36",
			want:      "Android",
		},
		{
			name:      "iOS iPhone",
			userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
			want:      "iOS",
		},
		{
			name:      "iOS iPad",
			userAgent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
			want:      "iOS",
		},
		{
			name:      "Linux",
			userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			want:      "Linux",
		},
		{
			name:      "Unknown OS",
			userAgent: "SomeUnknownBrowser/1.0",
			want:      "Other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectOS(tt.userAgent); got != tt.want {
				t.Errorf("detectOS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test isBot function
func TestIsBot(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      bool
	}{
		{
			name:      "Googlebot",
			userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			want:      true,
		},
		{
			name:      "YandexBot",
			userAgent: "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
			want:      true,
		},
		{
			name:      "Contains 'crawler'",
			userAgent: "SomeCrawler/1.0",
			want:      true,
		},
		{
			name:      "Contains 'spider'",
			userAgent: "WebSpider/2.0",
			want:      true,
		},
		{
			name:      "Regular Chrome browser",
			userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
			want:      false,
		},
		{
			name:      "Regular Firefox browser",
			userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
			want:      false,
		},
		{
			name:      "Bot with uppercase",
			userAgent: "MyBot/1.0",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBot(tt.userAgent); got != tt.want {
				t.Errorf("isBot() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test detectBot function
func TestDetectBot(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		{
			name:      "Googlebot",
			userAgent: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
			want:      "Googlebot",
		},
		{
			name:      "YandexBot",
			userAgent: "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
			want:      "YandexBot",
		},
		{
			name:      "AhrefsBot",
			userAgent: "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
			want:      "AhrefsBot",
		},
		{
			name:      "ChatGPT-User",
			userAgent: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
			want:      "ChatGPT-User",
		},
		{
			name:      "Bytespider",
			userAgent: "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)",
			want:      "Bytespider",
		},
		{
			name:      "PetalBot",
			userAgent: "Mozilla/5.0 (Linux; Android 7.0;) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)",
			want:      "PetalBot",
		},
		{
			name:      "Unknown bot",
			userAgent: "MyCustomBot/1.0",
			want:      "UnknownBot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectBot(tt.userAgent); got != tt.want {
				t.Errorf("detectBot() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Benchmark tests
func BenchmarkParseLine(b *testing.B) {
	line := `[u-0][08/Dec/2025:14:23:45 +0300] 0.123 0.456 200 192.168.1.1 example.com GET /api/users HTTP/1.1 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"`
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = parseLine(line)
	}
}

func BenchmarkDetectBrowser(b *testing.B) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detectBrowser(ua)
	}
}

func BenchmarkIsBot(b *testing.B) {
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = isBot(ua)
	}
}

// Test parseTimeFlag function
func TestParseTimeFlag(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		checkTime func(time.Time) bool
	}{
		{
			name:    "Valid time format",
			input:   "08/Dec/2025:14:30:45",
			wantErr: false,
			checkTime: func(tm time.Time) bool {
				return tm.Day() == 8 && tm.Month() == time.December &&
					tm.Year() == 2025 && tm.Hour() == 14 &&
					tm.Minute() == 30 && tm.Second() == 45
			},
		},
		{
			name:    "Another valid time",
			input:   "01/Jan/2024:00:00:00",
			wantErr: false,
			checkTime: func(tm time.Time) bool {
				return tm.Day() == 1 && tm.Month() == time.January &&
					tm.Year() == 2024 && tm.Hour() == 0
			},
		},
		{
			name:    "Empty string returns zero time",
			input:   "",
			wantErr: false,
			checkTime: func(tm time.Time) bool {
				return tm.IsZero()
			},
		},
		{
			name:    "Invalid format - wrong separator",
			input:   "08-Dec-2025:14:30:45",
			wantErr: true,
		},
		{
			name:    "Invalid format - missing time",
			input:   "08/Dec/2025",
			wantErr: true,
		},
		{
			name:    "Invalid format - wrong month",
			input:   "08/Abc/2025:14:30:45",
			wantErr: true,
		},
		{
			name:    "Invalid format - random string",
			input:   "not a valid time",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTimeFlag(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseTimeFlag() expected error for input %q, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("parseTimeFlag() unexpected error: %v", err)
				}
				if tt.checkTime != nil && !tt.checkTime(result) {
					t.Errorf("parseTimeFlag() time check failed for input %q, got %v", tt.input, result)
				}
			}
		})
	}
}

// Test time filtering in log analysis
func TestTimeFiltering(t *testing.T) {
	// Create a temporary test file with known log entries
	testLogs := `[u-0][08/Dec/2025:08:00:00 +0300] 0.1 0.1 200 192.168.1.1 example.com GET /early HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:12:00:00 +0300] 0.1 0.1 200 192.168.1.2 example.com GET /noon HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:18:00:00 +0300] 0.1 0.1 200 192.168.1.3 example.com GET /evening HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:23:00:00 +0300] 0.1 0.1 200 192.168.1.4 example.com GET /night HTTP/1.1 "Mozilla/5.0"`

	// Write test data to temp file
	tmpfile, err := createTempFile(testLogs)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer cleanupTempFile(tmpfile)

	tests := []struct {
		name          string
		fromTime      string
		toTime        string
		expectedCount int
	}{
		{
			name:          "No filter - all entries",
			fromTime:      "",
			toTime:        "",
			expectedCount: 4,
		},
		{
			name:          "Filter from noon",
			fromTime:      "08/Dec/2025:12:00:00",
			toTime:        "",
			expectedCount: 3, // noon, evening, night
		},
		{
			name:          "Filter until evening",
			fromTime:      "",
			toTime:        "08/Dec/2025:18:00:00",
			expectedCount: 3, // early, noon, evening
		},
		{
			name:          "Filter noon to evening",
			fromTime:      "08/Dec/2025:12:00:00",
			toTime:        "08/Dec/2025:18:00:00",
			expectedCount: 2, // noon, evening
		},
		{
			name:          "Filter specific hour",
			fromTime:      "08/Dec/2025:12:00:00",
			toTime:        "08/Dec/2025:12:59:59",
			expectedCount: 1, // only noon
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var startTime, endTime time.Time
			var err error

			if tt.fromTime != "" {
				startTime, err = parseTimeFlag(tt.fromTime)
				if err != nil {
					t.Fatalf("Failed to parse fromTime: %v", err)
				}
			}

			if tt.toTime != "" {
				endTime, err = parseTimeFlag(tt.toTime)
				if err != nil {
					t.Fatalf("Failed to parse toTime: %v", err)
				}
			}

			result, err := analyzeLog(tmpfile, startTime, endTime, nil, false, "", "", "", "", "")
			if err != nil {
				t.Fatalf("analyzeLog failed: %v", err)
			}

			if result.TotalRequests != tt.expectedCount {
				t.Errorf("Expected %d requests, got %d", tt.expectedCount, result.TotalRequests)
			}
		})
	}
}

// Helper function to create temporary test file
func createTempFile(content string) (string, error) {
	tmpfile, err := os.CreateTemp("", "loginspector-test-*.log")
	if err != nil {
		return "", err
	}
	if _, err := tmpfile.Write([]byte(content)); err != nil {
		_ = tmpfile.Close()
		_ = os.Remove(tmpfile.Name())
		return "", err
	}
	if err := tmpfile.Close(); err != nil {
		_ = os.Remove(tmpfile.Name())
		return "", err
	}
	return tmpfile.Name(), nil
}

// Helper function to cleanup temporary test file
func cleanupTempFile(path string) {
	_ = os.Remove(path)
}

// Test parseStatusCodes function
func TestParseStatusCodes(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantCodes []string
	}{
		{
			name:      "Single exact code",
			input:     "200",
			wantErr:   false,
			wantCodes: []string{"200"},
		},
		{
			name:      "Multiple exact codes",
			input:     "200,404,500",
			wantErr:   false,
			wantCodes: []string{"200", "404", "500"},
		},
		{
			name:      "Single range",
			input:     "4xx",
			wantErr:   false,
			wantCodes: []string{"4xx"},
		},
		{
			name:      "Multiple ranges",
			input:     "2xx,4xx,5xx",
			wantErr:   false,
			wantCodes: []string{"2xx", "4xx", "5xx"},
		},
		{
			name:      "Mixed exact and ranges",
			input:     "200,4xx,500",
			wantErr:   false,
			wantCodes: []string{"200", "4xx", "500"},
		},
		{
			name:      "With spaces",
			input:     "200, 404, 500",
			wantErr:   false,
			wantCodes: []string{"200", "404", "500"},
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: false,
		},
		{
			name:    "Invalid code - not a number",
			input:   "abc",
			wantErr: true,
		},
		{
			name:    "Invalid range - wrong digit",
			input:   "9xx",
			wantErr: true,
		},
		{
			name:    "Invalid range - 1xx",
			input:   "1xx",
			wantErr: true,
		},
		{
			name:    "Invalid code - too short",
			input:   "20",
			wantErr: true,
		},
		{
			name:    "Invalid code - too long",
			input:   "2000",
			wantErr: true,
		},
		{
			name:    "Invalid code - out of range",
			input:   "999",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseStatusCodes(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("parseStatusCodes() expected error for input %q, got nil", tt.input)
				}
			} else {
				if err != nil {
					t.Errorf("parseStatusCodes() unexpected error: %v", err)
				}
				if tt.wantCodes != nil && len(result) != len(tt.wantCodes) {
					t.Errorf("parseStatusCodes() got %d codes, want %d", len(result), len(tt.wantCodes))
				}
				for i, code := range tt.wantCodes {
					if result[i] != code {
						t.Errorf("parseStatusCodes() code[%d] = %q, want %q", i, result[i], code)
					}
				}
			}
		})
	}
}

// Test matchesStatusCode function
func TestMatchesStatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode string
		filters    []string
		want       bool
	}{
		{
			name:       "Exact match",
			statusCode: "200",
			filters:    []string{"200"},
			want:       true,
		},
		{
			name:       "No match",
			statusCode: "200",
			filters:    []string{"404"},
			want:       false,
		},
		{
			name:       "Range match - 4xx",
			statusCode: "404",
			filters:    []string{"4xx"},
			want:       true,
		},
		{
			name:       "Range match - 5xx",
			statusCode: "503",
			filters:    []string{"5xx"},
			want:       true,
		},
		{
			name:       "Range match - 2xx",
			statusCode: "201",
			filters:    []string{"2xx"},
			want:       true,
		},
		{
			name:       "No range match",
			statusCode: "200",
			filters:    []string{"4xx"},
			want:       false,
		},
		{
			name:       "Multiple filters - matches first",
			statusCode: "200",
			filters:    []string{"200", "404", "500"},
			want:       true,
		},
		{
			name:       "Multiple filters - matches middle",
			statusCode: "404",
			filters:    []string{"200", "404", "500"},
			want:       true,
		},
		{
			name:       "Multiple filters - matches last",
			statusCode: "500",
			filters:    []string{"200", "404", "500"},
			want:       true,
		},
		{
			name:       "Multiple filters - no match",
			statusCode: "301",
			filters:    []string{"200", "404", "500"},
			want:       false,
		},
		{
			name:       "Mixed filters - exact match",
			statusCode: "200",
			filters:    []string{"200", "4xx", "5xx"},
			want:       true,
		},
		{
			name:       "Mixed filters - range match",
			statusCode: "404",
			filters:    []string{"200", "4xx", "5xx"},
			want:       true,
		},
		{
			name:       "Empty filters",
			statusCode: "200",
			filters:    []string{},
			want:       true,
		},
		{
			name:       "Nil filters",
			statusCode: "200",
			filters:    nil,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesStatusCode(tt.statusCode, tt.filters)
			if result != tt.want {
				t.Errorf("matchesStatusCode(%q, %v) = %v, want %v", tt.statusCode, tt.filters, result, tt.want)
			}
		})
	}
}

// Test status code filtering integration
func TestStatusFiltering(t *testing.T) {
	// Create test log with various status codes
	testLogs := `[u-0][08/Dec/2025:08:00:00 +0300] 0.1 0.1 200 192.168.1.1 example.com GET /page1 HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:08:00:01 +0300] 0.1 0.1 201 192.168.1.2 example.com POST /api HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:08:00:02 +0300] 0.1 0.1 301 192.168.1.3 example.com GET /old HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:08:00:03 +0300] 0.1 0.1 404 192.168.1.4 example.com GET /missing HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:08:00:04 +0300] 0.1 0.1 500 192.168.1.5 example.com GET /error HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:08:00:05 +0300] 0.1 0.1 503 192.168.1.6 example.com GET /down HTTP/1.1 "Mozilla/5.0"`

	tmpfile, err := createTempFile(testLogs)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer cleanupTempFile(tmpfile)

	tests := []struct {
		name          string
		statusFilters []string
		excludeMode   bool
		expectedCount int
	}{
		{
			name:          "No filter - all entries",
			statusFilters: nil,
			excludeMode:   false,
			expectedCount: 6,
		},
		{
			name:          "Include exact code 200",
			statusFilters: []string{"200"},
			excludeMode:   false,
			expectedCount: 1,
		},
		{
			name:          "Include multiple exact codes",
			statusFilters: []string{"200", "404", "500"},
			excludeMode:   false,
			expectedCount: 3,
		},
		{
			name:          "Include range 2xx",
			statusFilters: []string{"2xx"},
			excludeMode:   false,
			expectedCount: 2, // 200, 201
		},
		{
			name:          "Include range 4xx",
			statusFilters: []string{"4xx"},
			excludeMode:   false,
			expectedCount: 1, // 404
		},
		{
			name:          "Include ranges 4xx,5xx",
			statusFilters: []string{"4xx", "5xx"},
			excludeMode:   false,
			expectedCount: 3, // 404, 500, 503
		},
		{
			name:          "Include mixed 200,4xx",
			statusFilters: []string{"200", "4xx"},
			excludeMode:   false,
			expectedCount: 2, // 200, 404
		},
		{
			name:          "Exclude exact code 200",
			statusFilters: []string{"200"},
			excludeMode:   true,
			expectedCount: 5, // All except 200
		},
		{
			name:          "Exclude range 2xx",
			statusFilters: []string{"2xx"},
			excludeMode:   true,
			expectedCount: 4, // All except 200, 201
		},
		{
			name:          "Exclude ranges 2xx,3xx",
			statusFilters: []string{"2xx", "3xx"},
			excludeMode:   true,
			expectedCount: 3, // Only 404, 500, 503
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := analyzeLog(tmpfile, time.Time{}, time.Time{}, tt.statusFilters, tt.excludeMode, "", "", "", "", "")
			if err != nil {
				t.Fatalf("analyzeLog failed: %v", err)
			}

			if result.TotalRequests != tt.expectedCount {
				t.Errorf("Expected %d requests, got %d", tt.expectedCount, result.TotalRequests)
			}
		})
	}
}

// Test FilteredEntries storage and domain parsing
func TestFilteredEntries(t *testing.T) {
	testLogs := `[u-0][08/Dec/2025:08:00:00 +0300] 0.1 0.1 200 192.168.1.1 example.com GET /page1 HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:08:00:01 +0300] 0.2 0.2 404 192.168.1.2 test.com GET /missing HTTP/1.1 "Mozilla/5.0"
[u-0][08/Dec/2025:08:00:02 +0300] 0.3 0.3 500 192.168.1.3 api.example.com POST /error HTTP/1.1 "Mozilla/5.0"`

	tmpfile, err := createTempFile(testLogs)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer cleanupTempFile(tmpfile)

	tests := []struct {
		name               string
		statusFilters      []string
		excludeMode        bool
		expectedEntryCount int
		checkFirstEntry    func(*LogEntry) bool
	}{
		{
			name:               "All entries stored with domains",
			statusFilters:      nil,
			excludeMode:        false,
			expectedEntryCount: 3,
			checkFirstEntry: func(e *LogEntry) bool {
				return e.StatusCode == "200" &&
					e.Domain == "example.com" &&
					e.IP == "192.168.1.1" &&
					e.Path == "/page1"
			},
		},
		{
			name:               "Only 404s stored",
			statusFilters:      []string{"404"},
			excludeMode:        false,
			expectedEntryCount: 1,
			checkFirstEntry: func(e *LogEntry) bool {
				return e.StatusCode == "404" &&
					e.Domain == "test.com" &&
					e.Path == "/missing"
			},
		},
		{
			name:               "Exclude 2xx - errors stored",
			statusFilters:      []string{"2xx"},
			excludeMode:        true,
			expectedEntryCount: 2,
			checkFirstEntry: func(e *LogEntry) bool {
				return e.StatusCode == "404" && e.Domain == "test.com"
			},
		},
		{
			name:               "Check domain extraction",
			statusFilters:      []string{"500"},
			excludeMode:        false,
			expectedEntryCount: 1,
			checkFirstEntry: func(e *LogEntry) bool {
				return e.Domain == "api.example.com" &&
					e.Method == "POST" &&
					e.TotalTime == 0.3
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := analyzeLog(tmpfile, time.Time{}, time.Time{}, tt.statusFilters, tt.excludeMode, "", "", "", "", "")
			if err != nil {
				t.Fatalf("analyzeLog failed: %v", err)
			}

			if len(result.FilteredEntries) != tt.expectedEntryCount {
				t.Errorf("Expected %d filtered entries, got %d", tt.expectedEntryCount, len(result.FilteredEntries))
			}

			if len(result.FilteredEntries) > 0 && tt.checkFirstEntry != nil {
				if !tt.checkFirstEntry(&result.FilteredEntries[0]) {
					t.Errorf("First entry check failed for %+v", result.FilteredEntries[0])
				}
			}
		})
	}
}
