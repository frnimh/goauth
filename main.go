package main

import (
	"gopkg.in/yaml.v3"
	"encoding/json"
	"github.com/xeipuuv/gojsonschema"
	"fmt"
    "io"
    "os"
    "strings"
    "time"
    "log"
	"net"
    "net/http"
    "net/url"
    "crypto/tls"
)

type Config struct {
	Users map[string]UserConfig `yaml:"users"`
}

type UserConfig struct {
	Password string   `yaml:"password"`
	Path     string   `yaml:"path"`
	Methods  []string `yaml:"methos"`
}

func main() {
	// Get YAML configuration file from environment variable
	configFile := os.Getenv("AUTH_CONFIG_FILE")
	if configFile == "" {
		configFile = "config.yaml" // Default file
	}

	// Validate the YAML configuration file with the schema
	validateYAMLWithSchema(configFile)

	// Parse configuration file after validation
	file, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer file.Close()

	var config Config
	if err := yaml.NewDecoder(file).Decode(&config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// Get environment variables
	authType := os.Getenv("AUTH_TYPE")
	if authType == "" {
		authType = "none"
	}
	authUpstream := os.Getenv("AUTH_UPSTREAM")
	if authUpstream == "" {
		log.Fatal("AUTH_UPSTREAM must be set")
	}
	authPort := os.Getenv("AUTH_PORT")
	if authPort == "" {
		authPort = "8080"
	}

	// Configure HTTP handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		logRequest(r) // Log each request
	
		if authType != "none" {
			username, password, ok := r.BasicAuth()
			if !ok {
				// Send `WWW-Authenticate` header to trigger login popup
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
	
			userConfig, exists := config.Users[username]
			if !exists || userConfig.Password != password {
				// Send `WWW-Authenticate` header to trigger login popup
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
	
			// Allow exact matches and sub-paths
			if r.URL.Path != strings.TrimSuffix(userConfig.Path, "/") &&
			   !strings.HasPrefix(r.URL.Path, userConfig.Path) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
	
			// Check if the HTTP method is allowed
			if !methodAllowed(r.Method, userConfig.Methods) {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
	
		// Proxy request to upstream
		proxyRequest(w, r, authUpstream)
	}
	
	http.HandleFunc("/", handler)

	// Start server
	log.Printf("Starting server on port %s...", authPort)
	log.Fatal(http.ListenAndServe(":"+authPort, nil))
}

func methodAllowed(method string, allowedMethods []string) bool {
	for _, m := range allowedMethods {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func proxyRequest(w http.ResponseWriter, r *http.Request, upstream string) {
    // Parse the upstream URL
    parsedUpstream, err := url.Parse(upstream)
    if err != nil {
        log.Printf("Invalid upstream URL: %v", err)
        http.Error(w, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    // Log the upstream address and schema
    log.Printf("Proxying request to upstream: %s (schema: %s)", parsedUpstream.Host, parsedUpstream.Scheme)

    // Modify the request URL to point to the upstream server
    r.URL.Scheme = parsedUpstream.Scheme
    r.URL.Host = parsedUpstream.Host
    r.RequestURI = ""
    r.Host = parsedUpstream.Host

    // Set timeouts for the HTTP client to avoid indefinite waiting
    timeout := 10 * time.Second // Set a reasonable timeout (e.g., 10 seconds)

    // Create an HTTP client with TLS configuration allow Insecure TLS
    var client *http.Client
    if parsedUpstream.Scheme == "https" {
        // Create a custom HTTP client that conditionally skips certificate verification
        customTransport := &http.Transport{
            TLSClientConfig: &tls.Config{
                InsecureSkipVerify: true, // Use the value from AUTH_INSEC_UPSTREAM
            },
            // Set the timeout for the transport layer
            DialContext: (&net.Dialer{
                Timeout: timeout,
            }).DialContext,
            // Set the TLS handshake timeout (separate from the dial timeout)
            TLSHandshakeTimeout: timeout,
        }
        client = &http.Client{
            Transport: customTransport,
            Timeout:   timeout, // Set overall client timeout
        }
    } else {
        // Default HTTP client for non-HTTPS
        client = &http.Client{
            Timeout: timeout, // Set overall client timeout
        }
    }

    // Forward the request
    resp, err := client.Do(r)
    if err != nil {
        log.Printf("Error connecting to upstream server: %v", err)
        http.Error(w, "Failed to connect to upstream server", http.StatusBadGateway)
        return
    }
    defer resp.Body.Close()

    // Copy response from upstream server to the client
    for k, v := range resp.Header {
        w.Header()[k] = v
    }
    w.WriteHeader(resp.StatusCode)
    if _, err := io.Copy(w, resp.Body); err != nil {
        log.Printf("Failed to copy response body: %v", err)
    }
}


// logRequest logs details about the incoming HTTP request
func logRequest(r *http.Request) {
	log.Printf("Request: Method=%s, Path=%s, RemoteAddr=%s, Headers=%v",
		r.Method, r.URL.Path, r.RemoteAddr, r.Header)
}

func validateYAMLWithSchema(configFile string) {
	// Load the YAML schema file
	schemaFile, err := os.Open("yaml-schema.json") // Change to your actual JSON schema file path
	if err != nil {
		log.Fatalf("Failed to open schema file: %v", err)
	}
	defer schemaFile.Close()

	// Read the schema content
	schemaContent, err := io.ReadAll(schemaFile)
	if err != nil {
		log.Fatalf("Failed to read schema file: %v", err)
	}

	// Parse JSON schema
	schemaLoader := gojsonschema.NewStringLoader(string(schemaContent))

	// Load the YAML file
	yamlFile, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Failed to open YAML file: %v", err)
	}
	defer yamlFile.Close()

	// Read YAML content
	yamlContent, err := io.ReadAll(yamlFile)
	if err != nil {
		log.Fatalf("Failed to read YAML file: %v", err)
	}

	// Parse YAML content
	var yamlData interface{}
	err = yaml.Unmarshal(yamlContent, &yamlData)
	if err != nil {
		log.Fatalf("Failed to parse YAML: %v", err)
	}

	// Convert YAML to JSON format
	jsonData, err := json.Marshal(yamlData)
	if err != nil {
		log.Fatalf("Failed to convert YAML to JSON: %v", err)
	}

	// Load the JSON data for validation
	document := gojsonschema.NewStringLoader(string(jsonData))

	// Validate the YAML against the JSON schema
	result, err := gojsonschema.Validate(schemaLoader, document)
	if err != nil {
		log.Fatalf("YAML validation failed: %v", err)
	}
	if result.Valid() {
		fmt.Println("YAML file is valid according to the JSON schema!")
	} else {
		fmt.Printf("The document is not valid. See errors:\n")
		for _, desc := range result.Errors() {
			fmt.Printf("- %s\n", desc)
		}
		os.Exit(1) // Exit with an error code if validation fails
	}
}
