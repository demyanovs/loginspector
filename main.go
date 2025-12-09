package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "v0.1.0"

const (
	DefaultLimitIPs           = 10
	DefaultLimitStatus        = 10
	DefaultLimitPaths         = 10
	DefaultLimitBots          = 10
	MinRequestsForSignificant = 5
	ScannerBufferSize         = 1024 * 1024      // 1MB initial buffer
	ScannerMaxBufferSize      = 10 * 1024 * 1024 // 10MB max line size
	HoursInDay                = 24
)

type LogEntry struct {
	ProcessTime float64
	TotalTime   float64
	StatusCode  string
	IP          string
	Method      string
	Path        string
	UserAgent   string
	Hour        string
	Timestamp   time.Time
}

type Analysis struct {
	TotalRequests     int
	ByIP              map[string]int
	ByStatusCode      map[string]int
	ByBrowser         map[string]int
	ByDevice          map[string]int
	ByOS              map[string]int
	ByPath            map[string]int
	Bots              map[string]int
	IPBotInfo         map[string]string
	Errors            []LogEntry
	ErrorsByIP        map[string]int
	ForbiddenByIP     map[string]int
	AvgResponseTime   float64
	TotalResponseTime float64
	TimeDistribution  map[string]int
	UserRequests      int // Non-bot requests
}

var logRegex *regexp.Regexp

// init compiles the log parsing regex at startup and fails fast if regex is invalid.
func init() {
	// Compile regex at startup with error handling
	var err error
	logRegex, err = regexp.Compile(
		`\[.*?\]\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s.*?\]\s+([\d.]+)\s+([\d.]+)\s+(\d{3})\s+([\d.]+)\s+\S+\s+(GET|POST|HEAD|PUT|DELETE)\s+(\S+)\s+HTTP.*?"([^"]*)"`,
	)
	if err != nil {
		log.Fatalf("Failed to compile log regex: %v", err)
	}
}

// parseLine parses a single log line and extracts structured data.
// Returns LogEntry with parsed fields or an error if the line format is invalid.
func parseLine(line string) (*LogEntry, error) {
	match := logRegex.FindStringSubmatch(line)
	if match == nil {
		return nil, fmt.Errorf("line does not match expected format")
	}

	// Parse timestamp
	timestamp, err := time.Parse("02/Jan/2006:15:04:05", match[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	processTime, err := strconv.ParseFloat(match[2], 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse process time: %w", err)
	}

	totalTime, err := strconv.ParseFloat(match[3], 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse total time: %w", err)
	}

	return &LogEntry{
		ProcessTime: processTime,
		TotalTime:   totalTime,
		StatusCode:  match[4],
		IP:          match[5],
		Method:      match[6],
		Path:        match[7],
		UserAgent:   match[8],
		Hour:        fmt.Sprintf("%02d", timestamp.Hour()),
		Timestamp:   timestamp,
	}, nil
}

// parseTimeFlag parses a time string provided by the user via command-line flags.
// Accepts format: "08/Dec/2025:08:30:00"
// Returns parsed time or an error if the format is invalid.
func parseTimeFlag(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse("02/Jan/2006:15:04:05", s)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid time format '%s', expected format: DD/Mon/YYYY:HH:MM:SS (e.g., 08/Dec/2025:08:30:00)", s)
	}
	return t, nil
}

// parseStatusCodes parses a comma-separated list of status codes from user input.
// Accepts exact codes (200, 404) and ranges (2xx, 3xx, 4xx, 5xx).
// Returns a slice of status code patterns or an error if validation fails.
func parseStatusCodes(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}

	codes := strings.Split(s, ",")
	result := make([]string, 0, len(codes))

	for _, code := range codes {
		code = strings.TrimSpace(code)
		if code == "" {
			continue
		}

		// Validate format: either 3-digit code (100-599) or Nxx where N is 2-5
		if len(code) != 3 {
			return nil, fmt.Errorf("invalid status code '%s': must be 3 characters (e.g., 200, 4xx)", code)
		}

		// Check if it's a range pattern (Nxx)
		if code[1] == 'x' && code[2] == 'x' {
			firstDigit := code[0]
			if firstDigit < '2' || firstDigit > '5' {
				return nil, fmt.Errorf("invalid status code range '%s': range must be 2xx, 3xx, 4xx, or 5xx", code)
			}
			result = append(result, code)
		} else {
			// Exact code - validate it's a number
			statusNum, err := strconv.Atoi(code)
			if err != nil {
				return nil, fmt.Errorf("invalid status code '%s': must be a number or range (e.g., 200, 4xx)", code)
			}
			if statusNum < 100 || statusNum > 599 {
				return nil, fmt.Errorf("invalid status code '%s': must be between 100 and 599", code)
			}
			result = append(result, code)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no valid status codes provided")
	}

	return result, nil
}

// matchesStatusCode checks if a status code matches any of the provided filters.
// Supports exact matching (e.g., "404" matches filter "404") and range matching
// (e.g., "404" matches filter "4xx"). Returns true if any filter matches or if filters is empty.
func matchesStatusCode(statusCode string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}

	for _, filter := range filters {
		// Exact match
		if statusCode == filter {
			return true
		}

		// Range match (e.g., "404" matches "4xx")
		if len(filter) == 3 && filter[1] == 'x' && filter[2] == 'x' {
			if len(statusCode) >= 1 && statusCode[0] == filter[0] {
				return true
			}
		}
	}

	return false
}

// analyzeLog reads and analyzes the entire log file at the given path.
// It parses each line, aggregates statistics, and detects bots and user agents.
// Optional time filtering: pass zero value time.Time for startTime/endTime to disable filtering.
// Optional status filtering: pass statusFilters slice; excludeMode determines include/exclude behavior.
// Returns Analysis containing all statistics or an error if file cannot be read.
func analyzeLog(path string, startTime, endTime time.Time, statusFilters []string, excludeMode bool) (*Analysis, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Printf("Warning: failed to close file: %v", closeErr)
		}
	}()

	a := &Analysis{
		ByIP:             map[string]int{},
		ByStatusCode:     map[string]int{},
		ByBrowser:        map[string]int{},
		ByDevice:         map[string]int{},
		ByOS:             map[string]int{},
		ByPath:           map[string]int{},
		Bots:             map[string]int{},
		IPBotInfo:        map[string]string{},
		ErrorsByIP:       map[string]int{},
		ForbiddenByIP:    map[string]int{},
		TimeDistribution: map[string]int{},
	}

	// Buffered scanner with larger buffer for big files
	scanner := bufio.NewScanner(f)
	buf := make([]byte, ScannerBufferSize)
	scanner.Buffer(buf, ScannerMaxBufferSize)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		entry, err := parseLine(line)
		if err != nil {
			// Skip invalid lines silently
			continue
		}

		// Apply time range filtering if specified
		if !startTime.IsZero() && entry.Timestamp.Before(startTime) {
			continue
		}
		if !endTime.IsZero() && entry.Timestamp.After(endTime) {
			continue
		}

		// Apply status code filtering
		if len(statusFilters) > 0 {
			matches := matchesStatusCode(entry.StatusCode, statusFilters)
			if excludeMode && matches {
				continue // Exclude mode: skip if matches
			}
			if !excludeMode && !matches {
				continue // Include mode: skip if doesn't match
			}
		}

		a.TotalRequests++
		a.TotalResponseTime += entry.TotalTime

		a.ByIP[entry.IP]++
		a.ByStatusCode[entry.StatusCode]++
		a.ByPath[strings.Split(entry.Path, "?")[0]]++
		a.TimeDistribution[entry.Hour]++

		// Parse User-Agent for non-bots only
		if !isBot(entry.UserAgent) {
			a.UserRequests++
			a.ByBrowser[detectBrowser(entry.UserAgent)]++
			a.ByDevice[detectDevice(entry.UserAgent)]++
			a.ByOS[detectOS(entry.UserAgent)]++
		}

		// Errors
		if strings.HasPrefix(entry.StatusCode, "4") || strings.HasPrefix(entry.StatusCode, "5") {
			a.Errors = append(a.Errors, *entry)
			a.ErrorsByIP[entry.IP]++
		}

		// Track 403 Forbidden specifically
		if entry.StatusCode == "403" {
			a.ForbiddenByIP[entry.IP]++
		}

		// Bots
		if isBot(entry.UserAgent) {
			botName := detectBot(entry.UserAgent)
			a.Bots[botName]++
			a.IPBotInfo[entry.IP] = botName
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if a.TotalRequests > 0 {
		a.AvgResponseTime = a.TotalResponseTime / float64(a.TotalRequests)
	}

	return a, nil
}

// isBot checks if a User-Agent string belongs to a bot/crawler.
// It uses common bot patterns like "bot", "spider", "crawler" in the UA string.
func isBot(ua string) bool {
	uaLower := strings.ToLower(ua)
	return strings.Contains(uaLower, "bot") ||
		strings.Contains(uaLower, "crawler") ||
		strings.Contains(uaLower, "spider") ||
		strings.Contains(uaLower, "crawl")
}

// detectBrowser identifies the browser from a User-Agent string.
// Returns browser name like "Chrome", "Firefox", "Safari", "Edge", "Opera", "IE", or "Other".
func detectBrowser(ua string) string {
	if strings.Contains(ua, "Edg/") || strings.Contains(ua, "Edge/") {
		return "Edge"
	}
	if strings.Contains(ua, "OPR/") || strings.Contains(ua, "Opera/") {
		return "Opera"
	}
	if strings.Contains(ua, "Firefox/") {
		return "Firefox"
	}
	if strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Edg") {
		return "Chrome"
	}
	if strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Chromium") {
		return "Safari"
	}
	if strings.Contains(ua, "MSIE") || strings.Contains(ua, "Trident/") {
		return "Internet Explorer"
	}
	return "Other"
}

// detectDevice determines the device type from a User-Agent string.
// Returns "Mobile", "Tablet", or "Desktop".
func detectDevice(ua string) string {
	if strings.Contains(ua, "Tablet") || strings.Contains(ua, "iPad") {
		return "Tablet"
	}
	if strings.Contains(ua, "Mobile") || (strings.Contains(ua, "Android") && !strings.Contains(ua, "Tablet")) {
		return "Mobile"
	}
	return "Desktop"
}

// detectOS identifies the operating system from a User-Agent string.
// Returns OS name like "Windows", "macOS", "Linux", "Android", "iOS", or "Other".
func detectOS(ua string) string {
	if strings.Contains(ua, "Windows") {
		return "Windows"
	}
	if strings.Contains(ua, "Android") {
		return "Android"
	}
	if strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "iOS") {
		return "iOS"
	}
	if strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X") {
		return "macOS"
	}
	if strings.Contains(ua, "Linux") && !strings.Contains(ua, "Android") {
		return "Linux"
	}
	return "Other"
}

// detectBot identifies the specific bot name from a User-Agent string.
// It recognizes 40+ known bots including Googlebot, YandexBot, Bingbot, etc.
// Returns the bot name or "Other" if not recognized. Logs unknown bots in debug mode (DEBUG=1).
func detectBot(ua string) string {
	known := []string{
		"Googlebot",
		"Applebot",
		"bingbot",
		"YandexBot",
		"DuckDuckBot",
		"VKRobotRB",
		"AhrefsBot",
		"SemrushBot",
		"Baiduspider",
		"keys-so-bot",
		"PetalBot",
		"Bytespider",
		"TikTokSpider",
		"PerplexityBot",
		"YandexMetrika",
		"YandexAccessibilityBot",
		"YaDirectFetcher",
		"YandexImages",
		"YandexRenderResourcesBot",
		"YandexMobileBot",
		"coccocbot",
		"Cotoyogi",
		"GetIntent",
		"ChatGPT-User",
		"OAI-SearchBot",
		"Pinterestbot",
		"Sogou",
		"meta-externalagent",
		"AliyunSecBot",
		"HaloBot",
		"ShapBot",
		"Twitterbot",
		"TelegramBot",
		"Facebot",
		"SERankingBacklinksBot",
		"IABot",
		"trendictionbot",
	}
	for _, k := range known {
		if strings.Contains(ua, k) {
			return k
		}
	}

	return "UnknownBot"
}

type PrintOptions struct {
	Title              string
	Data               map[string]int
	Limit              int
	ShowTotal          bool
	ShowPercentage     bool
	TotalForPercentage int
	BotInfo            map[string]string
}

// printSectionHeader prints a formatted section header with the given title.
func printSectionHeader(title string) {
	fmt.Printf("\n========== %s ==========\n", title)
}

// printSorted prints statistics in sorted order with optional features.
// It supports limiting output, showing totals, percentages, and bot information.
// Options are configured via PrintOptions struct.
func printSorted(opts PrintOptions) {
	printSectionHeader(opts.Title)

	type kv struct {
		Key   string
		Value int
	}

	var arr []kv
	total := 0
	for k, v := range opts.Data {
		arr = append(arr, kv{k, v})
		total += v
	}

	sort.Slice(arr, func(i, j int) bool {
		return arr[i].Value > arr[j].Value
	})

	limit := opts.Limit
	if len(arr) < limit {
		limit = len(arr)
	}

	for i := 0; i < limit; i++ {
		key := arr[i].Key
		value := arr[i].Value

		if opts.ShowPercentage {
			percentage := float64(value) / float64(opts.TotalForPercentage) * 100
			fmt.Printf("%-30s %6.2f%% (%d requests)\n", key, percentage, value)
		} else if opts.BotInfo != nil {
			// IP with bot info
			if botName, isBot := opts.BotInfo[key]; isBot {
				fmt.Printf("%-40s %d (bot: %s)\n", key, value, botName)
			} else {
				fmt.Printf("%-40s %d\n", key, value)
			}
		} else {
			fmt.Printf("%-40s %d\n", key, value)
		}
	}

	if opts.ShowTotal {
		fmt.Printf("\nTotal: %d\n", total)
	}
}

// printTimeDistribution prints hourly request distribution (00:00-01:00, etc.).
// It displays all 24 hours even if some have zero requests.
func printTimeDistribution(title string, m map[string]int) {
	printSectionHeader(title)

	// Create array for all 24 hours
	hours := make([]int, HoursInDay)
	for hourStr, count := range m {
		hour, err := strconv.Atoi(hourStr)
		if err != nil || hour < 0 || hour >= HoursInDay {
			continue
		}
		hours[hour] = count
	}

	// Print hourly distribution
	for i := 0; i < HoursInDay; i++ {
		nextHour := (i + 1) % HoursInDay
		timeRange := fmt.Sprintf("%02d:00 - %02d:00", i, nextHour)
		fmt.Printf("%-20s %d\n", timeRange, hours[i])
	}
}

// printSuspiciousIPs analyzes and displays IPs with suspicious activity patterns.
// It identifies IPs with high error counts, high error rates (>20% with ≥5 requests),
// and many 403 Forbidden responses. Marks known bots in the output.
func printSuspiciousIPs(errorsByIP, forbiddenByIP, byIP map[string]int, botInfo map[string]string) {
	printSectionHeader("Suspicious IPs")

	type ipStat struct {
		IP        string
		Errors    int
		Total     int
		ErrorRate float64
		Forbidden int
		BotName   string
	}

	var stats []ipStat
	for ip, total := range byIP {
		errors := errorsByIP[ip]
		forbidden := forbiddenByIP[ip]
		if errors > 0 {
			stats = append(stats, ipStat{
				IP:        ip,
				Errors:    errors,
				Total:     total,
				ErrorRate: float64(errors) / float64(total) * 100,
				Forbidden: forbidden,
				BotName:   botInfo[ip],
			})
		}
	}

	// Sort by error count
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Errors > stats[j].Errors
	})

	// Print top IPs by errors
	fmt.Println("\nTop IPs by error count (4xx/5xx):")
	limit := DefaultLimitIPs
	if len(stats) < limit {
		limit = len(stats)
	}
	for i := 0; i < limit; i++ {
		s := stats[i]
		if s.BotName != "" {
			fmt.Printf("%-20s %4d errors (%5.1f%% error rate, %d total) (bot: %s)\n",
				s.IP, s.Errors, s.ErrorRate, s.Total, s.BotName)
		} else {
			fmt.Printf("%-20s %4d errors (%5.1f%% error rate, %d total)\n",
				s.IP, s.Errors, s.ErrorRate, s.Total)
		}
	}

	// Sort by error rate (minimum N requests to be significant)
	var significantStats []ipStat
	for _, s := range stats {
		if s.Total >= MinRequestsForSignificant {
			significantStats = append(significantStats, s)
		}
	}

	sort.Slice(significantStats, func(i, j int) bool {
		return significantStats[i].ErrorRate > significantStats[j].ErrorRate
	})

	fmt.Printf("\nTop IPs by error rate (min %d requests):\n", MinRequestsForSignificant)
	limit = DefaultLimitIPs
	if len(significantStats) < limit {
		limit = len(significantStats)
	}
	for i := 0; i < limit; i++ {
		s := significantStats[i]
		if s.BotName != "" {
			fmt.Printf("%-20s %5.1f%% error rate (%d/%d) (bot: %s)\n",
				s.IP, s.ErrorRate, s.Errors, s.Total, s.BotName)
		} else {
			fmt.Printf("%-20s %5.1f%% error rate (%d/%d)\n",
				s.IP, s.ErrorRate, s.Errors, s.Total)
		}
	}

	// Sort by 403 count
	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Forbidden > stats[j].Forbidden
	})

	fmt.Println("\nTop IPs by 403 Forbidden:")
	limit = DefaultLimitIPs
	if len(stats) < limit {
		limit = len(stats)
	}
	for i := 0; i < limit; i++ {
		s := stats[i]
		if s.Forbidden > 0 {
			if s.BotName != "" {
				fmt.Printf("%-20s %4d forbidden requests (bot: %s)\n", s.IP, s.Forbidden, s.BotName)
			} else {
				fmt.Printf("%-20s %4d forbidden requests\n", s.IP, s.Forbidden)
			}
		}
	}
}

// main is the entry point of the application.
// It parses command-line flags, analyzes the log file, and displays requested statistics.
func main() {
	// Section flags
	showIPs := flag.Bool("ips", false, "Top IPs - IP addresses with most requests (bots are marked)")
	showStatus := flag.Bool("status", false, "HTTP Status Codes - Server response distribution (200=OK, 301=Redirect, 404=NotFound, etc.)")
	showBrowser := flag.Bool("browser", false, "Browser Statistics - Browser usage distribution")
	showDevice := flag.Bool("device", false, "Device Statistics - Desktop vs Mobile vs Tablet")
	showOS := flag.Bool("os", false, "OS Statistics - Operating system distribution")
	showPaths := flag.Bool("paths", false, "Paths - Most requested URLs on your site (query params stripped)")
	showTime := flag.Bool("time", false, "Time Distribution - Request activity by hour (shows traffic patterns throughout the day)")
	showBots := flag.Bool("bots", false, "Bots - Identified bot/crawler traffic breakdown (Total shows all bot requests)")
	// Limit flag
	limit := flag.Int("limit", 0, "Override default limits - maximum number of items to show per section")
	// Time range filters
	fromTime := flag.String("from", "", "Filter logs from this time (format: 08/Dec/2025:08:30:00)")
	toTime := flag.String("to", "", "Filter logs until this time (format: 08/Dec/2025:18:30:00)")
	// Status code filters
	statusCode := flag.String("status-code", "", "Include only these status code(s) - comma-separated, supports ranges (e.g., \"200,4xx,500\")")
	excludeStatus := flag.String("exclude-status", "", "Exclude these status code(s) - comma-separated, supports ranges (e.g., \"301,3xx\")")

	flag.Parse()

	// Check if any section flag was explicitly set
	explicitMode := *showIPs || *showStatus || *showBrowser || *showDevice || *showOS || *showPaths || *showTime || *showBots

	// If no flags specified, enable all sections (default behavior)
	if !explicitMode {
		*showIPs = true
		*showStatus = true
		*showBrowser = true
		*showDevice = true
		*showOS = true
		*showPaths = true
		*showTime = true
		*showBots = true
	}

	// Default limits per section (if -limit not specified)
	limitIPs := DefaultLimitIPs
	limitStatus := DefaultLimitStatus
	limitPaths := DefaultLimitPaths
	limitBots := DefaultLimitBots

	// Override with custom limit if specified
	if *limit > 0 {
		limitIPs = *limit
		limitStatus = *limit
		limitPaths = *limit
		limitBots = *limit
	}

	if flag.NArg() < 1 {
		fmt.Println("Usage: loginspector [flags] access.log")
		fmt.Println("\nAnalyze web server access logs and display statistics")
		fmt.Println("\nSections (without flags all sections shown, with flags only specified ones):")
		fmt.Println("  -ips        Top IPs - IP addresses with most requests (bots are marked)")
		fmt.Println("  -status     HTTP Status Codes - Server response distribution")
		fmt.Println("  -browser    Browser Statistics - Browser usage (Chrome, Firefox, Safari, etc.)")
		fmt.Println("  -device     Device Statistics - Desktop, Mobile, Tablet distribution")
		fmt.Println("  -os         OS Statistics - Operating system distribution")
		fmt.Println("  -paths      Paths - Most requested URLs on your site")
		fmt.Println("  -time       Time Distribution - Request activity by hour")
		fmt.Println("  -bots       Bots - Identified bot/crawler traffic breakdown")
		fmt.Println("  suspicious  Suspicious IPs - IPs with high error rates (shown by default)")
		fmt.Println("\nOther flags:")
		fmt.Printf("  -limit int  Override default limits (IPs:%d, Status:%d, Paths:%d, Bots:%d)\n",
			DefaultLimitIPs, DefaultLimitStatus, DefaultLimitPaths, DefaultLimitBots)
		fmt.Println("  -from         Filter logs from this time (format: 08/Dec/2025:08:30:00)")
		fmt.Println("  -to           Filter logs until this time (format: 08/Dec/2025:18:30:00)")
		fmt.Println("  -status-code  Include only these status codes (comma-separated, ranges: 2xx,3xx,4xx,5xx)")
		fmt.Println("  -exclude-status Exclude these status codes (comma-separated, ranges: 2xx,3xx,4xx,5xx)")
		fmt.Println("\nExamples:")
		fmt.Println("  loginspector access.log              # Show all sections + suspicious IPs")
		fmt.Println("  loginspector -bots access.log        # Show only bots")
		fmt.Println("  loginspector -bots -ips access.log   # Show only bots and IPs")
		fmt.Println("  loginspector -bots -limit=50 access.log")
		fmt.Println("  loginspector -from=\"08/Dec/2025:08:00:00\" -to=\"08/Dec/2025:18:00:00\" access.log")
		fmt.Println("  loginspector -from=\"07/Dec/2025:12:00:00\" access.log  # From specific time onwards")
		fmt.Println("  loginspector -status-code=\"200\" access.log             # Only 200 OK responses")
		fmt.Println("  loginspector -status-code=\"4xx,5xx\" access.log        # Only errors")
		fmt.Println("  loginspector -exclude-status=\"2xx\" access.log         # All except success")
		fmt.Println("  loginspector -from=\"...\" -status-code=\"5xx\" access.log  # Combine filters")
		fmt.Println("\nNote: Suspicious IPs section (IPs with errors) is shown by default if errors exist")
		fmt.Println("\nEnvironment variables:")
		fmt.Println("  DEBUG=1     Enable verbose logging (unknown bots, etc.)")
		return
	}

	// Parse and validate time range filters
	var startTime, endTime time.Time
	var err error

	if *fromTime != "" {
		startTime, err = parseTimeFlag(*fromTime)
		if err != nil {
			log.Fatalf("Error parsing -from flag: %v", err)
		}
	}

	if *toTime != "" {
		endTime, err = parseTimeFlag(*toTime)
		if err != nil {
			log.Fatalf("Error parsing -to flag: %v", err)
		}
	}

	// Validate that start time is before end time
	if !startTime.IsZero() && !endTime.IsZero() && startTime.After(endTime) {
		log.Fatalf("Error: -from time (%s) cannot be after -to time (%s)", startTime.Format("02/Jan/2006:15:04:05"), endTime.Format("02/Jan/2006:15:04:05"))
	}

	// Parse and validate status code filters
	var statusFilters []string
	var excludeStatusMode bool

	// Check mutual exclusivity
	if *statusCode != "" && *excludeStatus != "" {
		log.Fatalf("Error: -status-code and -exclude-status cannot be used together")
	}

	if *statusCode != "" {
		statusFilters, err = parseStatusCodes(*statusCode)
		if err != nil {
			log.Fatalf("Error parsing -status-code flag: %v", err)
		}
		excludeStatusMode = false
	} else if *excludeStatus != "" {
		statusFilters, err = parseStatusCodes(*excludeStatus)
		if err != nil {
			log.Fatalf("Error parsing -exclude-status flag: %v", err)
		}
		excludeStatusMode = true
	}

	a, err := analyzeLog(flag.Arg(0), startTime, endTime, statusFilters, excludeStatusMode)
	if err != nil {
		log.Fatalf("Error analyzing log: %v", err)
	}

	fmt.Println("=========================================")
	fmt.Printf("        LogInspector (%s)\n", version)
	fmt.Println("=========================================")
	fmt.Printf("Total requests: %d\n", a.TotalRequests)
	fmt.Printf("Unique IPs: %d\n", len(a.ByIP))
	fmt.Printf("Errors (4xx/5xx): %d\n", len(a.Errors))
	fmt.Printf("Avg response time: %.3f s\n", a.AvgResponseTime)
	fmt.Printf("Bot types: %d\n", len(a.Bots))
	if len(a.ErrorsByIP) > 0 {
		fmt.Printf("IPs with errors: %d\n", len(a.ErrorsByIP))
	}
	fmt.Println("=========================================")

	if *showIPs {
		printSorted(PrintOptions{
			Title:   "Top IPs",
			Data:    a.ByIP,
			Limit:   limitIPs,
			BotInfo: a.IPBotInfo,
		})
	}

	if *showStatus {
		printSorted(PrintOptions{
			Title: "HTTP Status Codes",
			Data:  a.ByStatusCode,
			Limit: limitStatus,
		})
	}

	if *showBrowser && a.UserRequests > 0 {
		printSorted(PrintOptions{
			Title:              "Browser Statistics",
			Data:               a.ByBrowser,
			Limit:              len(a.ByBrowser),
			ShowPercentage:     true,
			TotalForPercentage: a.UserRequests,
		})
	}

	if *showDevice && a.UserRequests > 0 {
		printSorted(PrintOptions{
			Title:              "Device Statistics",
			Data:               a.ByDevice,
			Limit:              len(a.ByDevice),
			ShowPercentage:     true,
			TotalForPercentage: a.UserRequests,
		})
	}

	if *showOS && a.UserRequests > 0 {
		printSorted(PrintOptions{
			Title:              "OS Statistics",
			Data:               a.ByOS,
			Limit:              len(a.ByOS),
			ShowPercentage:     true,
			TotalForPercentage: a.UserRequests,
		})
	}

	if *showPaths {
		printSorted(PrintOptions{
			Title: "Paths",
			Data:  a.ByPath,
			Limit: limitPaths,
		})
	}

	if *showTime {
		printTimeDistribution("Time Distribution", a.TimeDistribution)
	}

	if *showBots {
		printSorted(PrintOptions{
			Title:     "Bots",
			Data:      a.Bots,
			Limit:     limitBots,
			ShowTotal: true,
		})
	}

	// Show Suspicious IPs only in non-explicit mode (when no section flags specified)
	if !explicitMode && len(a.ErrorsByIP) > 0 {
		printSuspiciousIPs(a.ErrorsByIP, a.ForbiddenByIP, a.ByIP, a.IPBotInfo)
	}
}
