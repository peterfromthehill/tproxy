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
	Port        int
	CertService services.CertService
}

func (api API) StartAPIServer() {
	log.Printf("API served on port %d", api.Port)
	r := mux.NewRouter()
	r.HandleFunc("/cache/", api.getHandler()).Methods("GET")
	r.HandleFunc("/cache/{domain}", api.getDomainHandler()).Methods("GET")
	r.HandleFunc("/cache/{domain}", api.deleteDomainHandler()).Methods("DELETE")
	r.HandleFunc("/cache/{domain}", api.addDomainHandler()).Methods("PUT")
	r.HandleFunc("/cache/{domain}", api.addDomainHandler()).Methods("POST")
	r.Path("/metrics").Handler(promhttp.Handler())
	log.Fatal(http.ListenAndServe(":"+fmt.Sprintf("%d", api.Port), r))
}

func (api API) getHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var domains []string
		for i := range api.CertService.CacheService.GetCopyOfCache() {
			domains = append(domains, i)
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(domains)
	}
}

func (api API) getDomainHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		fmt.Printf("get /cache/%s", domain)
		dom, err := api.CertService.CacheService.FindCertinCache(domain)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		cer, err := x509.ParseCertificate(dom.Certificate[0])
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(cer.NotAfter.String()))
	}
}

func (api API) deleteDomainHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		api.CertService.CacheService.Delete(domain)
		w.WriteHeader(http.StatusOK)
	}
}

func (api API) addDomainHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := mux.Vars(r)["domain"]
		_, err := api.CertService.GenerateCertByName(domain)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		w.WriteHeader(http.StatusOK)
	}
}
