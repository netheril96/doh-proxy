package main

import (
	"context"
	"flag"
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
	googleDNS          = "8.8.8.8:53"
	ipv4SubnetMask     = 24
	ipv6SubnetMask     = 56
	shutdownTimeout    = 5 * time.Second
	dohMimeType        = "application/dns-message"
	forwardedForHeader = "X-Forwarded-For"
)

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

	// Create and attach EDNS0 subnet option
	opt := msg.IsEdns0()
	if opt == nil {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		msg.Extra = append(msg.Extra, opt)
	}

	ecs := new(dns.EDNS0_SUBNET)
	ecs.Code = dns.EDNS0SUBNET
	ecs.Address = clientIP
	if clientIP.To4() != nil {
		ecs.Family = 1 // IPv4
		ecs.SourceNetmask = ipv4SubnetMask
	} else {
		ecs.Family = 2 // IPv6
		ecs.SourceNetmask = ipv6SubnetMask
	}
	ecs.SourceScope = 0
	opt.Option = append(opt.Option, ecs)

	// Forward the query to the upstream DNS server
	dnsClient := new(dns.Client)
	respMsg, _, err := dnsClient.Exchange(msg, googleDNS)
	if err != nil {
		log.Printf("DNS exchange with %s failed: %v", googleDNS, err)
		http.Error(w, "DNS query failed", http.StatusServiceUnavailable)
		return
	}

	// Pack the response message
	respBody, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack DNS response", http.StatusInternalServerError)
		return
	}

	// Send the response back to the client
	w.Header().Set("Content-Type", dohMimeType)
	w.WriteHeader(http.StatusOK)
	w.Write(respBody)
}
