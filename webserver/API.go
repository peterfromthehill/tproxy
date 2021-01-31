package webserver

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/peterfromthehill/tproxy/services"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type API struct {
	Port int
}

func (api API) StartAPIServer() {
	log.Printf("API served on port %d", api.Port)
	r := mux.NewRouter()
	r.HandleFunc("/cache/", getHandler()).Methods("GET")
	r.HandleFunc("/cache/{domain}", getDomainHandler()).Methods("GET")
	r.HandleFunc("/cache/{domain}", deleteDomainHandler()).Methods("DELETE")
	r.HandleFunc("/cache/{domain}", addDomainHandler()).Methods("PUT")
	r.HandleFunc("/cache/{domain}", addDomainHandler()).Methods("POST")
	r.Path("/metrics").Handler(promhttp.Handler())
	log.Fatal(http.ListenAndServe(":"+fmt.Sprintf("%d", api.Port), r))
}

func getHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var domains []string
		cacheService := services.GetCacheService()
		for i := range cacheService.GetCopyOfCache() {
			domains = append(domains, i)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(domains)
	}
}

func getDomainHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		fmt.Printf("get /cache/%s", domain)
		cacheService := services.GetCacheService()
		dom, err := cacheService.FindCertinCache(domain)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		cer, err := x509.ParseCertificate(dom.Certificate[0])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(cer.NotAfter.String()))
	}
}

func deleteDomainHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		cacheService := services.GetCacheService()
		cacheService.Delete(domain)
		w.WriteHeader(http.StatusOK)
	}
}

func addDomainHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		_, err := services.GenerateCertByName(domain)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		w.WriteHeader(http.StatusOK)
	}
}
