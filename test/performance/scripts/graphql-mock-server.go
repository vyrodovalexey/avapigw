// graphql-mock-server.go - Standalone GraphQL mock backend for performance testing.
// Usage: go run graphql-mock-server.go [-port 8901] [-port2 8902]
// Serves POST /graphql and GET /health endpoints.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

type graphQLRequest struct {
	Query         string                 `json:"query"`
	OperationName string                 `json:"operationName,omitempty"`
	Variables     map[string]interface{} `json:"variables,omitempty"`
}

func resolveResponse(query string) string {
	q := strings.ToLower(strings.TrimSpace(query))

	switch {
	case strings.Contains(q, "__schema"):
		return `{"data":{"__schema":{"types":[{"name":"Query"},{"name":"Item"},{"name":"Mutation"},{"name":"String"},{"name":"Int"},{"name":"Boolean"}]}}}`
	case strings.Contains(q, "__type"):
		return `{"data":{"__type":{"name":"Item","fields":[{"name":"id"},{"name":"name"},{"name":"description"},{"name":"price"},{"name":"quantity"},{"name":"category"}]}}}`
	case strings.Contains(q, "__typename"):
		return `{"data":{"__typename":"Query"}}`
	case strings.Contains(q, "createitem") || strings.Contains(q, "mutation"):
		return `{"data":{"createItem":{"id":"4","name":"New Item","description":"Created via mutation","price":29.99,"quantity":10,"category":"new"}}}`
	case strings.Contains(q, "item(") || strings.Contains(q, "$id"):
		return `{"data":{"item":{"id":"1","name":"Item 1","description":"A test item","price":19.99,"quantity":100,"category":"electronics"}}}`
	case strings.Contains(q, "items"):
		return `{"data":{"items":[{"id":"1","name":"Item 1","description":"First item","price":19.99,"quantity":100,"category":"electronics"},{"id":"2","name":"Item 2","description":"Second item","price":29.99,"quantity":50,"category":"books"},{"id":"3","name":"Item 3","description":"Third item","price":9.99,"quantity":200,"category":"clothing"}]}}`
	default:
		return `{"data":{"result":"ok"}}`
	}
}

func graphqlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"errors":[{"message":"method not allowed"}]}`, http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"message":"failed to read body"}]}`)
		return
	}
	defer r.Body.Close()

	var gqlReq graphQLRequest
	if err := json.Unmarshal(body, &gqlReq); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"errors":[{"message":"invalid JSON"}]}`)
		return
	}

	response := resolveResponse(gqlReq.Query)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, response)
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy"}`)
}

func startServer(port int, wg *sync.WaitGroup) {
	defer wg.Done()

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", graphqlHandler)
	mux.HandleFunc("/health", healthHandler)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("GraphQL mock server starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server on %s failed: %v", addr, err)
	}
}

func main() {
	port1 := flag.Int("port", 8901, "First server port")
	port2 := flag.Int("port2", 8902, "Second server port")
	flag.Parse()

	var wg sync.WaitGroup
	wg.Add(2)

	go startServer(*port1, &wg)
	go startServer(*port2, &wg)

	log.Printf("GraphQL mock servers running on ports %d and %d", *port1, *port2)
	wg.Wait()
}
