package main

import (
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
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

	file, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer file.Close()

	// Parse configuration
	var config Config
	if err := yaml.NewDecoder(file).Decode(&config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// Get environment variables
	authType := os.Getenv("AUTH_TYPE")
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
	// Log the upstream address
	log.Printf("Proxying request to upstream: %s", upstream)

	// Modify the request URL to point to the upstream server
	r.URL.Scheme = "http"
	r.URL.Host = upstream
	r.RequestURI = ""
	r.Host = upstream

	// Forward the request
	client := &http.Client{}
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
