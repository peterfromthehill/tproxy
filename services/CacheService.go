package services

import (
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"
)

// SSLCache cached TLS certificates from sites visited in the history

type CacheService struct {
	sslCache map[string]SSLEntry
}

var cacheSericeInstance *CacheService
var onlyOneCacheService sync.Once

func GetCacheService() *CacheService {
	onlyOneCacheService.Do(func() {
		cacheSericeInstance = &CacheService{
			sslCache: make(map[string]SSLEntry),
		}
		_ = cacheSericeInstance
	})
	return cacheSericeInstance
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

func (this *CacheService) GetCopyOfCache() map[string]SSLEntry {
	newMap := make(map[string]SSLEntry)
	for k, v := range this.sslCache {
		newMap[k] = v
	}
	return newMap
}

func (this *CacheService) sslCacheWatcher0() {
	for i, v := range this.sslCache {
		cer, err := ParseX509Cert(v.certPEM.Bytes())
		if err != nil {
			log.Printf("%s: invalid cert!", i)
			continue
		}
		if cer.NotAfter.Before(time.Now().Add(time.Minute * 5)) {
			log.Printf("%s: cert expired, delete it from cache", i)
			this.Delete(i)
			continue
		}
		log.Printf("%s %s\n", i, cer.NotAfter)
	}
}

func (this *CacheService) Add(serverName string, entry SSLEntry) {
	this.sslCache[serverName] = entry
}

func (this *CacheService) Delete(serverName string) {
	delete(this.sslCache, serverName)
}

func (this *CacheService) HasServerName(serverName string) bool {
	_, ok := this.sslCache[serverName]
	return ok
}

func (this *CacheService) GetEntry(serverName string) (SSLEntry, bool) {
	sslEntry, ok := this.sslCache[serverName]
	return sslEntry, ok
}

func (this *CacheService) FindCertinCache(serverName string) (*tls.Certificate, error) {
	if sslEntry, ok := this.GetEntry(serverName); ok != false {
		serverCert, err := tls.X509KeyPair(sslEntry.certPEM.Bytes(), sslEntry.certPrivKeyPEM.Bytes())
		if err != nil {
			return nil, err
		}
		return &serverCert, nil
	}
	return nil, fmt.Errorf("%s Cert not found in cache", serverName)
}
