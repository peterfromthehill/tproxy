package services

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"time"
)

type CacheService struct {
	sslCache map[string]*tls.Certificate
}

func Init() *CacheService {
	return &CacheService{
		sslCache: make(map[string]*tls.Certificate),
	}
}

func (this *CacheService) Watch() {
	go this.sslCacheWatcher(10)
}

func (this *CacheService) sslCacheWatcher(interval time.Duration) {
	for {
		this.sslCacheWatcher0()
		time.Sleep(interval * time.Second)
	}
}

func (this *CacheService) GetCopyOfCache() map[string]tls.Certificate {
	newMap := make(map[string]tls.Certificate)
	for k, v := range this.sslCache {
		newMap[k] = *v
	}
	return newMap
}

func (this *CacheService) sslCacheWatcher0() {
	for i, v := range this.sslCache {
		if len(v.Certificate) < 1 {
			log.Printf("%s has no certificates", i)
			continue
		}
		cer, err := x509.ParseCertificate(v.Certificate[0])
		if err != nil {
			log.Printf("%s: invalid cert!", i)
			continue
		}
		log.Printf("%s: %s", i, cer.NotAfter)
		if cer.NotAfter.Before(time.Now().Add(time.Minute * 5)) {
			log.Printf("%s: cert expired, delete it from cache", i)
			this.Delete(i)
			continue
		}
	}
}

func (this *CacheService) Add(serverName string, entry *tls.Certificate) {
	this.sslCache[serverName] = entry
}

func (this *CacheService) Delete(serverName string) {
	delete(this.sslCache, serverName)
}

func (this *CacheService) HasServerName(serverName string) bool {
	_, ok := this.sslCache[serverName]
	return ok
}

func (this *CacheService) GetEntry(serverName string) (*tls.Certificate, bool) {
	sslEntry, ok := this.sslCache[serverName]
	return sslEntry, ok
}

func (this *CacheService) FindCertinCache(serverName string) (*tls.Certificate, error) {
	if sslEntry, ok := this.GetEntry(serverName); ok != false {
		return sslEntry, nil
	}
	return nil, fmt.Errorf("%s Cert not found in cache", serverName)
}
