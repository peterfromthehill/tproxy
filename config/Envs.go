package config

import "os"

const HTTP_PORT = "HTTP_PORT"
const HTTPS_PORT = "HTTPS_PORT"
const SSLKEY_FILE = "SSLKEY_FILE"
const SSLCERT_FILE = "SSLCERT_FILE"

type Envs struct {
}

func getAllEnvs() []string {
	return []string{HTTP_PORT, HTTPS_PORT, SSLKEY_FILE, SSLCERT_FILE}
}

func (e Envs) VerifyEnvs() {
	for _, e := range getAllEnvs() {
		if os.Getenv(e) == "" {
			panic(e + " dont set")
		}
	}
}
