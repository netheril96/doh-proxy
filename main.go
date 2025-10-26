package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const (
	googleDoHUpstream  = "https://dns.google/dns-query"
	ipv4SubnetMask     = 24
	ipv6SubnetMask     = 56
	shutdownTimeout    = 5 * time.Second
	dohMimeType        = "application/dns-message"
	forwardedForHeader = "X-Forwarded-For"
	upstreamTimeout    = 4 * time.Second
)

// httpClient is a reusable HTTP client for forwarding DoH queries.
// It's configured with a timeout and is safe for concurrent use.
var httpClient = &http.Client{
	// Using a timeout shorter than the server's shutdown timeout.
	Timeout: upstreamTimeout,
}

func main() {
	socketPath := flag.String("socket", "/tmp/doh-proxy.sock", "Path to the Unix domain socket")
	flag.Parse()

	if *socketPath == "" {
		log.Fatal("Socket path cannot be empty")
	}

	// Set up signal handling for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Create the Unix socket listener
	// Ensure the socket file does not already exist
	if err := os.RemoveAll(*socketPath); err != nil {
		log.Fatalf("Failed to remove existing socket file: %v", err)
	}

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on unix socket %s: %v", *socketPath, err)
	}
	log.Printf("Listening on unix socket: %s", *socketPath)

	// Set permissions on the socket file
	if err := os.Chmod(*socketPath, 0666); err != nil {
		log.Printf("Warning: could not chmod socket file: %v", err)
	}

	// Set up HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", dnsQueryHandler)

	server := &http.Server{
		Handler: mux,
	}

	// Start the server in a goroutine
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-stop
	log.Println("Shutting down server...")

	// Create a context with a timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Println("Server gracefully stopped")
}

func dnsQueryHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests for DoH queries
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the DNS query from the request body
	queryBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Parse the DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(queryBody); err != nil {
		http.Error(w, "Failed to parse DNS query", http.StatusBadRequest)
		return
	}

	// Get client IP from X-Forwarded-For header
	clientIPStr := r.Header.Get(forwardedForHeader)
	if clientIPStr == "" {
		http.Error(w, "X-Forwarded-For header is missing", http.StatusBadRequest)
		return
	}

	// The header can contain a comma-separated list of IPs. The first one is the original client.
	ips := r.Header["X-Forwarded-For"]
	if len(ips) > 0 {
		clientIPStr = ips[0]
	}

	clientIP := net.ParseIP(clientIPStr)
	if clientIP == nil {
		http.Error(w, "Invalid IP address in X-Forwarded-For header", http.StatusBadRequest)
		return
	}

	// Truncate the client IP for privacy, as requested.
	var truncatedIP net.IP
	if clientIP.To4() != nil {
		mask := net.CIDRMask(ipv4SubnetMask, 32)
		truncatedIP = clientIP.Mask(mask)
	} else {
		mask := net.CIDRMask(ipv6SubnetMask, 128)
		truncatedIP = clientIP.Mask(mask)
	}

	// Create and attach EDNS0 subnet option
	opt := msg.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		msg.Extra = append([]dns.RR{opt}, msg.Extra...)
	}

	ecs := new(dns.EDNS0_SUBNET)
	ecs.Code = dns.EDNS0SUBNET
	ecs.Address = truncatedIP
	if truncatedIP.To4() != nil {
		ecs.Family = 1 // IPv4
		ecs.SourceNetmask = ipv4SubnetMask
	} else {
		ecs.Family = 2 // IPv6
		ecs.SourceNetmask = ipv6SubnetMask
	}
	ecs.SourceScope = 0
	opt.Option = append(opt.Option, ecs)

	// Pack the modified DNS query to be sent upstream.
	packedQuery, err := msg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS query for upstream", http.StatusInternalServerError)
		return
	}

	// Forward the query to the upstream DoH server.
	// We use the original request's context to handle cancellation.
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, googleDoHUpstream, bytes.NewReader(packedQuery))
	if err != nil {
		log.Printf("Failed to create upstream request: %v", err)
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}
	upstreamReq.Header.Set("Content-Type", dohMimeType)
	upstreamReq.Header.Set("Accept", dohMimeType)

	upstreamResp, err := httpClient.Do(upstreamReq)
	if err != nil {
		log.Printf("Upstream DoH query to %s failed: %v", googleDoHUpstream, err)
		http.Error(w, "DNS query failed", http.StatusServiceUnavailable)
		return
	}
	defer upstreamResp.Body.Close()

	if upstreamResp.StatusCode != http.StatusOK {
		log.Printf("Upstream DoH server returned status: %s", upstreamResp.Status)
		http.Error(w, fmt.Sprintf("Upstream error: %s", upstreamResp.Status), http.StatusBadGateway)
		return
	}

	respBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	// Send the response back to the client
	w.Header().Set("Content-Type", dohMimeType)
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}
