package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color" // For colorful output
)

// Special characters to test
var specialChars = []string{"<", ">", "\"", "'", "&", ";", "(", ")", "/", "\\", "%", "#", "@", "!", "*", "+"}

// Normal text for initial reflection check
const normalText = "sabdop"

var outputFile *os.File
var processedFile = "processed.txt"
var wafResults = make(map[string]string)
var wafMutex = &sync.Mutex{}
var processedURLs []string
var results []string
var resultsMutex = &sync.Mutex{}

// Colors for output
var green = color.New(color.FgGreen).SprintFunc()
var red = color.New(color.FgRed).SprintFunc()
var yellow = color.New(color.FgYellow).SprintFunc()
var blue = color.New(color.FgBlue).SprintFunc()

type ReflectionResult struct {
	Param string
	Chars []string
}

func main() {
	// Command-line arguments
	customHeader := flag.String("h", "", "Custom header (e.g., 'Key: Value')")
	outputPath := flag.String("o", "", "Output file to save results")
	customPayload := flag.String("p", "", "Custom payload to test (e.g., '<script>alert('xss')</script>')")
	checkWAF := flag.Bool("w", false, "Enable WAF detection with wafw00f")
	parallelDegree := flag.Int("d", 10, "Number of parallel threads for reflection checking (default: 10)")
	flag.Parse()

	// Set up output file if specified
	if *outputPath != "" {
		var err error
		outputFile, err = os.Create(*outputPath)
		if err != nil {
			fmt.Println(red("Error creating output file:"), err)
			os.Exit(1)
		}
		defer outputFile.Close()
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// Set up signal handling for interruption
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	go handleInterrupt(signals)

	// Read URLs from stdin (e.g., piped from `cat url.txt`)
	scanner := bufio.NewScanner(os.Stdin)
	uniqueDomains := make(map[string]bool)
	urls := make([]string, 0)

	for scanner.Scan() {
		targetURL := strings.TrimSpace(scanner.Text())
		if targetURL == "" {
			continue
		}

		// Validate URL
		if _, err := url.Parse(targetURL); err != nil {
			logResult(red(fmt.Sprintf("Invalid URL: %s\n", targetURL)))
			continue
		}

		urls = append(urls, targetURL)
		domain := extractDomain(targetURL)
		uniqueDomains[domain] = true
	}

	// Process URLs (CSP and Reflection)
	for _, targetURL := range urls {
		logResult(blue(fmt.Sprintf("Testing URL: %s\n", targetURL)))
		logResult("CSP:\n")
		checkCSP(targetURL, client, *customHeader)

		logResult("Reflection:\n")
		parsedURL, _ := url.Parse(targetURL)
		queryParams := parsedURL.Query()

		logResult("Parameters:\n")
		// Step 1: Check if normal text is reflected
		normalReflected := false
		for param := range queryParams {
			injectedValue := normalText
			queryParams.Set(param, injectedValue)
			parsedURL.RawQuery = queryParams.Encode()
			testURL := parsedURL.String()

			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				logResult(red(fmt.Sprintf("  Error creating request for normal text in param '%s': %v\n", param, err)))
				continue
			}
			if *customHeader != "" {
				parts := strings.SplitN(*customHeader, ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				logResult(red(fmt.Sprintf("  Error testing normal text in param '%s': %v\n", param, err)))
				continue
			}
			defer resp.Body.Close()

			body, _ := ioutil.ReadAll(resp.Body)
			if strings.Contains(string(body), injectedValue) {
				normalReflected = true
				break
			}
		}

		if !normalReflected {
			logResult(yellow("  Not reflected\n"))
		} else {
			// Step 2: Use parallel processing for special character checks if normal text is reflected
			resultsChan := make(chan ReflectionResult, len(queryParams)*len(specialChars))
			var wg sync.WaitGroup
			sem := make(chan struct{}, *parallelDegree)

			for param := range queryParams {
				for _, char := range specialChars {
					wg.Add(1)
					sem <- struct{}{} // Acquire a semaphore slot
					go func(p, c string, qp url.Values) {
						defer wg.Done()
						defer func() { <-sem }() // Release the semaphore slot

						// Create a deep copy of queryParams for this goroutine
						queryParamsCopy := url.Values{}
						for key, values := range qp {
							queryParamsCopy[key] = append([]string{}, values...)
						}

						// Create a deep copy of parsedURL for this goroutine
						parsedURLCopy := *parsedURL

						injectedValue := normalText + c
						queryParamsCopy.Set(p, injectedValue)
						parsedURLCopy.RawQuery = queryParamsCopy.Encode()
						testURL := parsedURLCopy.String()

						req, err := http.NewRequest("GET", testURL, nil)
						if err != nil {
							logResult(red(fmt.Sprintf("  Error creating request for char '%s' in param '%s': %v\n", c, p, err)))
							return
						}
						if *customHeader != "" {
							parts := strings.SplitN(*customHeader, ":", 2)
							if len(parts) == 2 {
								req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
							}
						}

						resp, err := client.Do(req)
						if err != nil {
							logResult(red(fmt.Sprintf("  Error testing char '%s' in param '%s': %v\n", c, p, err)))
							return
						}
						defer resp.Body.Close()

						body, _ := ioutil.ReadAll(resp.Body)
						if strings.Contains(string(body), injectedValue) {
							resultsChan <- ReflectionResult{Param: p, Chars: []string{c}}
						}
					}(param, char, queryParams)
				}
			}

			go func() {
				wg.Wait()
				close(resultsChan)
			}()

			// Aggregate results
			reflections := make(map[string][]string)
			for result := range resultsChan {
				reflections[result.Param] = append(reflections[result.Param], result.Chars...)
			}

			for param, chars := range reflections {
				if len(chars) > 0 {
					logResult(green(fmt.Sprintf("  %s : %s\n", param, strings.Join(chars, ""))))
				}
			}
		}

		if *customPayload != "" {
			logResult("Custom Payload Test:\n")
			for param := range queryParams {
				injectedPayload := normalText + *customPayload
				queryParams.Set(param, injectedPayload)
				parsedURL.RawQuery = queryParams.Encode()
				testURL := parsedURL.String()

				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					logResult(red(fmt.Sprintf("  Error creating request for payload: %v\n", err)))
					continue
				}
				if *customHeader != "" {
					parts := strings.SplitN(*customHeader, ":", 2)
					if len(parts) == 2 {
						req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
					}
				}

				resp, err := client.Do(req)
				if err != nil {
					logResult(red(fmt.Sprintf("  Error testing payload: %v\n", err)))
					continue
				}
				defer resp.Body.Close()

				body, _ := ioutil.ReadAll(resp.Body)
				if strings.Contains(string(body), injectedPayload) {
					logResult(green(fmt.Sprintf("  [+] '%s' reflected in '%s' with param '%s'\n", *customPayload, testURL, param)))
				} else {
					logResult(red(fmt.Sprintf("  [-] '%s' not reflected in '%s' with param '%s'\n", *customPayload, testURL, param)))
				}
			}
		}

		processedURLs = append(processedURLs, targetURL)
	}

	// WAF detection if -w flag is provided
	if *checkWAF {
		logResult(blue("WAF detection enabled. Analyzing unique domains and checking WAF...\n"))
		for domain := range uniqueDomains {
			if wafResults[domain] == "" {
				wafResult := checkWAFWithWafw00f(domain)
				wafMutex.Lock()
				wafResults[domain] = wafResult
				wafMutex.Unlock()
				logResult(fmt.Sprintf("  Domain: %s - %s\n", domain, wafResult))
			} else {
				logResult(fmt.Sprintf("  Domain: %s - %s (cached)\n", domain, wafResults[domain]))
			}
		}
	}

	// Save processed data
	saveProcessedData()

	if err := scanner.Err(); err != nil {
		logResult(red(fmt.Sprintf("Error reading input: %v\n", err)))
		os.Exit(1)
	}
}

func logResult(result string) {
	fmt.Print(result)
	resultsMutex.Lock()
	results = append(results, result)
	resultsMutex.Unlock()
	if outputFile != nil {
		// Strip ANSI color codes for file output
		plainResult := strings.ReplaceAll(result, "\x1b[32m", "") // Green
		plainResult = strings.ReplaceAll(plainResult, "\x1b[31m", "") // Red
		plainResult = strings.ReplaceAll(plainResult, "\x1b[33m", "") // Yellow
		plainResult = strings.ReplaceAll(plainResult, "\x1b[34m", "") // Blue
		plainResult = strings.ReplaceAll(plainResult, "\x1b[0m", "")  // Reset
		_, err := outputFile.WriteString(plainResult)
		if err != nil {
			fmt.Println(red("Error writing to output file:"), err)
		}
	}
}

func checkCSP(urlStr string, client *http.Client, customHeader string) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		logResult(red(fmt.Sprintf("  Error creating request: %v\n", err)))
		return
	}
	if customHeader != "" {
		parts := strings.SplitN(customHeader, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		logResult(red(fmt.Sprintf("  Error fetching URL: %v\n", err)))
		return
	}
	defer resp.Body.Close()

	csp := resp.Header.Get("Content-Security-Policy")
	if csp != "" {
		logResult(green(fmt.Sprintf("  [+] CSP Detected: %s\n", csp)))
	} else {
		logResult(yellow("  [-] No CSP header found.\n"))
	}
}

func checkWAFWithWafw00f(domain string) string {
	cmd := exec.Command("wafw00f", "http://"+domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return red(fmt.Sprintf("Error running wafw00f: %v", err))
	}

	wafOutput := string(output)
	for _, line := range strings.Split(wafOutput, "\n") {
		if strings.Contains(line, "is behind") {
			parts := strings.Split(line, "is behind")
			if len(parts) > 1 {
				wafInfo := strings.TrimSpace(parts[1])
				return green(fmt.Sprintf("WAF Detected: %s", strings.TrimSuffix(wafInfo, ".")))
			}
		}
	}
	return yellow("No WAF detected or unknown WAF")
}

func extractDomain(urlStr string) string {
	u, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	if parts := strings.Split(host, "."); len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

func saveProcessedData() {
	data := "Processed URLs:\n" + strings.Join(processedURLs, "\n") + "\n\nResults:\n" + strings.Join(results, "")
	err := ioutil.WriteFile(processedFile, []byte(data), 0644)
	if err != nil {
		fmt.Println(red("Error saving processed data:"), err)
	}
}

func handleInterrupt(signals chan os.Signal) {
	<-signals
	saveProcessedData()
	fmt.Println(red("\nInterrupted. Processed data saved to", processedFile))
	os.Exit(1)
}