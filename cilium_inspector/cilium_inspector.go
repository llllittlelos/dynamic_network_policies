package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"io/ioutil"

	"github.com/cilium/cilium/pkg/client"
	"gopkg.in/yaml.v3"
)

func main() {
	ciliumClient, err := client.NewDefaultClient()
	if err != nil {
		panic(err)
	}
	saveEndpointsToFile(ciliumClient)
	saveServicesToFile(ciliumClient)

	http.HandleFunc("/endpoints", func(w http.ResponseWriter, r *http.Request) {
		getEndpointsHandler(ciliumClient, w, r)
	})
	http.HandleFunc("/services", func(w http.ResponseWriter, r *http.Request) {
		getServicesHandler(ciliumClient, w, r)
	})

	fmt.Println("server is running on port: 64444")
	http.ListenAndServe(":64444", nil)
}

func saveEndpointsToFile(c *client.Client) {
	endpoints, err := c.EndpointList()
	if err != nil {
		panic(err)
	}

	jsonData, err := json.Marshal(endpoints)
	if err != nil {
		panic(err)
	}

	var yamlData interface{}
	err = yaml.Unmarshal(jsonData, &yamlData)
	if err != nil {
		panic(err)
	}

	yamlBytes, err := yaml.Marshal(yamlData)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("endpoints.yaml", yamlBytes, 0644)
	if err != nil {
		panic(err)
	}
}

func saveServicesToFile(c *client.Client) {
	services, err := c.GetServices()
	if err != nil {
		panic(err)
	}

	jsonData, err := json.Marshal(services)
	if err != nil {
		panic(err)
	}

	var yamlData interface{}
	err = yaml.Unmarshal(jsonData, &yamlData)
	if err != nil {
		panic(err)
	}

	yamlBytes, err := yaml.Marshal(yamlData)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile("services.yaml", yamlBytes, 0644)
	if err != nil {
		panic(err)
	}
}

func getEndpointsHandler(c *client.Client, w http.ResponseWriter, r *http.Request) {
	endpoints, err := c.EndpointList()
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

func getServicesHandler(c *client.Client, w http.ResponseWriter, r *http.Request) {
	services, err := c.GetServices()
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


