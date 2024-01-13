package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/pkg/client"
)

func main() {
	http.HandleFunc("/endpoints", getEndpointsHandler)
	http.HandleFunc("/services", getServicesHandler)

	fmt.Println("server is running on port: 64444")
	http.ListenAndServe(":64444", nil)
}

func getEndpointsHandler(w http.ResponseWriter, r *http.Request) {
	ciliumClient, err := client.NewDefaultClient()
	if err != nil {
		panic(err)
	}

	endpoints, err := ciliumClient.EndpointList()
	if err != nil {
		panic(err)
	}

	// Convert endpoints to JSON
	responseJSON, err := json.Marshal(endpoints)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set Content-Type header
	w.Header().Set("Content-Type", "application/json")

	// Write JSON response
	w.Write(responseJSON)
}

func getServicesHandler(w http.ResponseWriter, r *http.Request) {
	ciliumClient, err := client.NewDefaultClient()
	if err != nil {
		panic(err)
	}

	services, err := ciliumClient.GetServices()
	if err != nil {
		panic(err)
	}

	// Convert services to JSON
	responseJSON, err := json.Marshal(services)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set Content-Type header
	w.Header().Set("Content-Type", "application/json")

	// Write JSON response
	w.Write(responseJSON)
}


