package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

var (
	policies []Policy
	cache    *Cache
)

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if cached, ok := cache.get(req); ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cached)
		return
	}

	start := time.Now()
	resp := evaluate(policies, req)
	latency := time.Since(start).Milliseconds()

	cache.set(req, resp)

	log.Printf("[%s] subject=%s resource=%s action=%s riskScore=%.0f decision=%s latency=%dms",
		resp.Decision, req.Subject, req.Resource, req.Action, req.RiskScore, resp.Decision, latency)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

func main() {
	var err error
	policies, err = loadPolicies("policies.yaml")
	if err != nil {
		log.Fatalf("failed to load policies: %v", err)
	}
	log.Printf("loaded %d policies", len(policies))

	cache = newCache()

	http.HandleFunc("/authorize", authorizeHandler)
	http.HandleFunc("/health", healthHandler)

	log.Println("PDP listening on :8001")
	if err := http.ListenAndServe(":8001", nil); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
