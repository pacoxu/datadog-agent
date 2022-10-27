package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <server_addr> <number_of_requests>", os.Args[0])
	}

	serverAddr := os.Args[1]
	reqCount, err := strconv.Atoi(os.Args[2])
	if err != nil || reqCount < 0 {
		log.Fatalf("invalid value \"%s\"for number of request", os.Args[2])
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Needed to give time to the tracer to hook GoTLS functions
	time.Sleep(1 * time.Second)

	// When
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://%s/%d/request", serverAddr, http.StatusOK), nil)
	if err != nil {
		log.Fatalf("could not generate HTTP request: %s", err)
	}

	for i := 0; i < reqCount; i++ {
		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("could not do HTTPS request: %s", err)
		}

		_, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("could not read response body: %s", err)
		}

		resp.Body.Close()
	}

}
