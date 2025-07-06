package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Default patterns to detect secrets
var defaultSecretPatterns = map[string]string{
	"api_key":       `(?i)(api|access|secret)[-_]?key["']?\s*[:=]\s*["']([a-z0-9]{32,})`,
	"password":      `(?i)(password|passwd|pwd)["']?\s*[:=]\s*["']([^"'\s]+)`,
	"private_key":   `-----BEGIN (RSA|OPENSSH|DSA|EC|PGP)? PRIVATE KEY-----`,
	"oauth_token":   `(?i)oauth[-_]?token["']?\s*[:=]\s*["']([a-z0-9]{32,})`,
	"slack_token":   `(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`,
	"aws_key":       `(?i)(aws|amazon)[-_]?(access|secret)[-_]?key["']?\s*[:=]\s*["']([a-z0-9]{40})`,
	"high_entropy":  `([a-z0-9+/=]{32,})`, // Simple pattern for high entropy strings
	"database_url":  `(?i)(postgres|mysql|mongodb)://[a-z0-9_]+:[^@]+@[a-z0-9.-]+/[a-z0-9_]+`,
	"authorization": `(?i)authorization:\s*(bearer|basic)\s+([a-z0-9._-]+)`,
}

// File extensions to scan
var scanExtensions = []string{
	".yml", ".yaml", ".json", ".js", ".py", ".rb",
	".php", ".java", ".go", ".sh", ".env", ".config",
	".pem", ".ppk", ".key", ".sql", ".xml", ".conf",
}

// Directories to skip
var skipDirs = []string{
	"node_modules", ".git", "vendor", "dist", "build",
	"__pycache__", ".idea", ".vscode", "tmp", "log",
}

// Secret represents a found secret in a file
type Secret struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Type    string `json:"type"`
	Match   string `json:"match"`
	Context string `json:"context"`
}

// PatternConfig represents a custom pattern from YAML
type PatternConfig struct {
	Pattern struct {
		Name  string `yaml:"name"`
		Regex string `yaml:"regex"`
	} `yaml:"pattern"`
}

// Config represents the YAML configuration file structure
type Config struct {
	Patterns []PatternConfig `yaml:"patterns"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run() error {
	// Parse command line flags
	args, err := parseFlags()
	if err != nil {
		return err
	}

	if args.help {
		printHelp()
		return nil
	}

	// Initialize secret patterns
	secretPatterns := make(map[string]*regexp.Regexp)
	for name, pattern := range defaultSecretPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile pattern %s: %v", name, err)
		}
		secretPatterns[name] = re
	}

	// Load custom patterns if provided
	if args.patternsFile != "" {
		customPatterns, err := loadCustomPatterns(args.patternsFile)
		if err != nil {
			return fmt.Errorf("failed to load custom patterns: %v", err)
		}
		for name, re := range customPatterns {
			secretPatterns[name] = re
		}
	}

	// Determine the directory to scan
	var scanDir string
	var cleanup func() error

	if args.repoURL != "" {
		scanDir, cleanup, err = cloneGitRepo(args.repoURL)
		if err != nil {
			return fmt.Errorf("failed to clone repository: %v", err)
		}
		defer func() {
			if cleanup != nil {
				if err := cleanup(); err != nil {
					log.Printf("Warning: failed to clean up temporary directory: %v", err)
				}
			}
		}()
	} else if args.dirPath != "" {
		scanDir = args.dirPath
	} else {
		return fmt.Errorf("either --repo or --dir must be provided")
	}

	log.Printf("Scanning %s for potential secrets...\n", scanDir)

	// Scan the directory
	secrets, err := scanDirectory(scanDir, secretPatterns, args.ignoreFiles)
	if err != nil {
		return fmt.Errorf("scan failed: %v", err)
	}

	// Print results
	if err := printResults(secrets, args.jsonOutput, args.outputFile); err != nil {
		return fmt.Errorf("failed to print results: %v", err)
	}

	return nil
}

func parseFlags() (*struct {
	help        bool
	jsonOutput  bool
	outputFile  string
	patternsFile string
	ignoreFiles []string
	repoURL     string
	dirPath     string
}, error) {
	args := &struct {
		help        bool
		jsonOutput  bool
		outputFile  string
		patternsFile string
		ignoreFiles []string
		repoURL     string
		dirPath     string
	}{}

	// Simple flag parsing (for a real project, consider using the flag package)
	for i := 0; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "-h", "--help":
			args.help = true
		case "--json":
			args.jsonOutput = true
		case "--output-file":
			if i+1 >= len(os.Args) {
				return nil, fmt.Errorf("missing argument for --output-file")
			}
			args.outputFile = os.Args[i+1]
			i++
		case "--patterns":
			if i+1 >= len(os.Args) {
				return nil, fmt.Errorf("missing argument for --patterns")
			}
			args.patternsFile = os.Args[i+1]
			i++
		case "--ignore-files":
			if i+1 >= len(os.Args) {
				return nil, fmt.Errorf("missing argument for --ignore-files")
			}
			args.ignoreFiles = strings.Split(os.Args[i+1], ",")
			i++
		case "--repo":
			if i+1 >= len(os.Args) {
				return nil, fmt.Errorf("missing argument for --repo")
			}
			args.repoURL = os.Args[i+1]
			i++
		case "--dir":
			if i+1 >= len(os.Args) {
				return nil, fmt.Errorf("missing argument for --dir")
			}
			args.dirPath = os.Args[i+1]
			i++
		}
	}

	return args, nil
}

func printHelp() {
	helpText := `
Usage: leaquor [options]

Options:
  -h, --help          Display this help message.
  --json              Output results in JSON format.
  --output-file FILE  Write JSON results to the specified file.
  --patterns FILE     Load additional patterns from a YAML file.
  --ignore-files LIST Comma-separated list of files to ignore (e.g., "file1.txt,file2.json").
  --repo URL          Clone and scan a GitHub repository (e.g., https://github.com/user/repo.git).
  --dir PATH          Scan a specific directory on the file system.

Arguments:
  Either --repo or --dir must be provided.

Examples:
  leaquor --repo https://github.com/user/repo.git --json --output-file out.json
  leaquor --dir ./my_project --patterns custom_patterns.yaml | jq .
`
	fmt.Fprintln(os.Stderr, helpText)
}

func cloneGitRepo(repoURL string) (string, func() error, error) {
	// Validate URL
	if _, err := url.Parse(repoURL); err != nil {
		return "", nil, fmt.Errorf("invalid repository URL: %v", err)
	}

	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "leaquor-")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp directory: %v", err)
	}

	log.Printf("Cloning repository from %s into %s...\n", repoURL, tempDir)

	// Clone the repository
	cmd := exec.Command("git", "clone", repoURL, tempDir)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(tempDir)
		return "", nil, fmt.Errorf("git clone failed: %v", err)
	}

	log.Println("Repository cloned successfully.")

	cleanup := func() error {
		log.Println("Cleaning up temporary directory...")
		return os.RemoveAll(tempDir)
	}

	return tempDir, cleanup, nil
}

func loadCustomPatterns(yamlFile string) (map[string]*regexp.Regexp, error) {
	data, err := os.ReadFile(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %v", err)
	}

	patterns := make(map[string]*regexp.Regexp)
	for _, entry := range config.Patterns {
		re, err := regexp.Compile(entry.Pattern.Regex)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern %s: %v", entry.Pattern.Name, err)
		}
		patterns[entry.Pattern.Name] = re
	}

	return patterns, nil
}

func shouldSkip(path string, ignoreFiles []string) bool {
	// Check if path matches any ignored file names or patterns
	for _, file := range ignoreFiles {
		if strings.Contains(filepath.Base(path), file) {
			return true
		}
	}

	// Check if path matches any skipped directories
	for _, skip := range skipDirs {
		if strings.Contains(path, skip) {
			return true
		}
	}

	return false
}

func isTextFile(filepath string) bool {
	file, err := os.Open(filepath)
	if err != nil {
		log.Printf("Warning: Could not open file %s: %v\n", filepath, err)
		return false
	}
	defer file.Close()

	buf := make([]byte, 512) // Check first 512 bytes
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Warning: Could not read file %s: %v\n", filepath, err)
		return false
	}

	buf = buf[:n]

	// Check for non-text bytes (0-8, 14-31, except \t, \n, \r)
	for _, b := range buf {
		if b < 32 && b != 9 && b != 10 && b != 13 {
			return false
		}
	}

	return true
}

func calculateEntropy(s string) float64 {
	if len(s) < 16 {
		return 0.0 // Skip short strings
	}

	freq := make(map[rune]int)
	for _, c := range strings.ToLower(s) {
		freq[c]++
	}

	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func scanFile(filepath string, secretPatterns map[string]*regexp.Regexp) ([]Secret, error) {
	var secrets []Secret

	if !isTextFile(filepath) {
		return nil, nil
	}

	content, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filepath, err)
	}

	contentStr := string(content)

	// Check for each secret pattern
	for patternName, re := range secretPatterns {
		matches := re.FindAllStringSubmatchIndex(contentStr, -1)
		for _, m := range matches {
			var secret string
			if len(m) > 2 { // Has capturing groups
				secret = contentStr[m[2]:m[3]]
			} else {
				secret = contentStr[m[0]:m[1]]
			}

			// Skip empty matches
			if secret == "" {
				continue
			}

			// For high entropy pattern, verify entropy
			if patternName == "high_entropy" {
				entropy := calculateEntropy(secret)
				if entropy < 3.5 {
					continue // Skip low entropy strings
				}
			}

			line := getLineNumber(contentStr, m[0])
			context := getLine(contentStr, m[0])
			context = strings.Map(func(r rune) rune {
				if r >= 0 && r <= 31 {
					return -1 // Remove control characters
				}
				return r
			}, context)

			secrets = append(secrets, Secret{
				File:    filepath,
				Line:    line,
				Type:    patternName,
				Match:   secret,
				Context: context,
			})
		}
	}

	// Special case for private keys - check the whole file
	if secretPatterns["private_key"].MatchString(contentStr) {
		secrets = append(secrets, Secret{
			File:    filepath,
			Line:    1,
			Type:    "private_key",
			Match:   "PRIVATE KEY BLOCK",
			Context: "Contains private key material",
		})
	}

	return secrets, nil
}

func getLineNumber(content string, offset int) int {
	line := 1
	for i, c := range content {
		if i >= offset {
			break
		}
		if c == '\n' {
			line++
		}
	}
	return line
}

func getLine(content string, offset int) string {
	start := strings.LastIndex(content[:offset], "\n")
	if start == -1 {
		start = 0
	} else {
		start++ // Skip the newline character
	}

	end := strings.Index(content[offset:], "\n")
	if end == -1 {
		end = len(content)
	} else {
		end += offset
	}

	return content[start:end]
}

func scanDirectory(rootDir string, secretPatterns map[string]*regexp.Regexp, ignoreFiles []string) ([]Secret, error) {
	var secrets []Secret
	var mu sync.Mutex // Protects the secrets slice
	var wg sync.WaitGroup

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Skip unwanted directories
			if shouldSkip(path, ignoreFiles) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip ignored files and non-target extensions
		if shouldSkip(path, ignoreFiles) || !hasValidExtension(path) {
			return nil
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			found, err := scanFile(path, secretPatterns)
			if err != nil {
				log.Printf("Error scanning file %s: %v\n", path, err)
				return
			}

			if len(found) > 0 {
				mu.Lock()
				secrets = append(secrets, found...)
				mu.Unlock()
			}
		}()

		return nil
	})

	wg.Wait() // Wait for all file scans to complete

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %v", err)
	}

	return secrets, nil
}

func hasValidExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	for _, validExt := range scanExtensions {
		if ext == validExt {
			return true
		}
	}
	return false
}

func printResults(secrets []Secret, jsonOutput bool, outputFile string) error {
	if len(secrets) == 0 {
		if jsonOutput {
			_, err := fmt.Println("[]")
			return err
		}
		log.Println("No secrets found!")
		return nil
	}

	if jsonOutput {
		jsonData, err := json.MarshalIndent(secrets, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}

		if outputFile != "" {
			if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
				return fmt.Errorf("failed to write JSON output to file: %v", err)
			}
			log.Printf("JSON results written to %s\n", outputFile)
		} else {
			fmt.Println(string(jsonData))
		}
	} else {
		log.Printf("\nFound %d potential secrets:\n", len(secrets))
		log.Println(strings.Repeat("=", 60))

		for _, secret := range secrets {
			log.Printf("\nFile: %s\n", secret.File)
			log.Printf("Line: %d\n", secret.Line)
			log.Printf("Type: %s\n", secret.Type)
			log.Printf("Match: %s\n", secret.Match)
			log.Printf("Context: %s\n", secret.Context)
			log.Println(strings.Repeat("-", 60))
		}
	}

	return nil
}
