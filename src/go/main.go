package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"
)

const (
	x25519MLKEM768 tls.CurveID = 4588
	mlkemPublicKeySize           = 1184
	x25519PublicKeySize          = 32
)

var architectures = []string{"A0_SHARED", "A1_LABEL_ONLY", "A2_GLOBAL_SPLIT_SHAM", "A3_ROLE_ROUTED", "A4_HEDGED"}
var recipes = []string{"nominal", "origin_rng_state_reuse", "origin_rng_and_context_reuse"}

type deterministicReader struct {
	key          [32]byte
	lengthCounts map[int]uint64
	readSizes    []int
	reads        int
	bytes        int
}

type readerStats struct {
	Reads     int
	Bytes     int
	ReadSizes []int
	Roles     []string
}

type auditedReader interface {
	io.Reader
	stats() readerStats
}

func newReader(parts ...[]byte) *deterministicReader {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return &deterministicReader{key: key, lengthCounts: make(map[int]uint64)}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	r.reads++
	r.readSizes = append(r.readSizes, len(p))
	// Go deliberately performs an optional one-byte read in some crypto APIs.
	// Indexing deterministic blocks by requested length makes a modeled reader
	// state rollback invariant to that anti-test-coupling read without changing
	// any output length consumed by the cryptographic implementation.
	callIndex := r.lengthCounts[len(p)]
	if len(p) != 1 {
		r.lengthCounts[len(p)]++
	}
	generated := make([]byte, 0, len(p))
	for block := uint64(0); len(generated) < len(p); block++ {
		h := sha256.New()
		h.Write([]byte("P01-GO-TLS-RNG-V1"))
		h.Write(r.key[:])
		h.Write(uint64Bytes(uint64(len(p))))
		h.Write(uint64Bytes(callIndex))
		h.Write(uint64Bytes(block))
		generated = append(generated, h.Sum(nil)...)
	}
	copy(p, generated[:len(p)])
	r.bytes += len(p)
	return len(p), nil
}

func (r *deterministicReader) stats() readerStats {
	return readerStats{
		Reads:     r.reads,
		Bytes:     r.bytes,
		ReadSizes: append([]int(nil), r.readSizes...),
	}
}

// roleRoutedReader is an experiment-only realization of component-scoped
// entropy domains over Go's single tls.Config.Rand interface. The mapping is
// pinned to the audited Go 1.24/1.26 ClientHello call sequence and is not a
// production recommendation: a production API must identify the role
// explicitly instead of inferring it from call order.
type roleRoutedReader struct {
	architecture string
	recipe       string
	trial        int
	nonOneReads  int
	readSizes    []int
	roles        []string
	reads        int
	bytes        int
}

func roleForIndex(index int) string {
	roles := []string{"client_hello_random", "legacy_session_id", "x25519_scalar", "mlkem_seed"}
	if index >= 0 && index < len(roles) {
		return roles[index]
	}
	return fmt.Sprintf("unexpected_read_%d", index)
}

func (r *roleRoutedReader) Read(p []byte) (int, error) {
	r.reads++
	r.readSizes = append(r.readSizes, len(p))
	role := "optional_antitesting_byte"
	if len(p) != 1 {
		role = roleForIndex(r.nonOneReads)
		r.nonOneReads++
	}
	r.roles = append(r.roles, role)

	event := r.recipe != "nominal"
	contextReset := r.recipe == "origin_rng_and_context_reuse"
	trialBytes := uint64Bytes(uint64(r.trial))
	zeroBytes := uint64Bytes(0)
	index := trialBytes
	label := []byte("shared-config-domain")

	switch r.architecture {
	case "A0_SHARED":
		if event {
			index = zeroBytes
		}
	case "A1_LABEL_ONLY":
		label = []byte("label-only:" + role)
		if event {
			index = zeroBytes
		}
	case "A2_GLOBAL_SPLIT_SHAM":
		// The separate global crypto/rand reader is intentionally not used by
		// this Go TLS path. Config.Rand remains one rolled-back domain.
		label = []byte("config-domain")
		if event {
			index = zeroBytes
		}
	case "A3_ROLE_ROUTED":
		label = []byte("component-domain:" + role)
		if event && role == "mlkem_seed" {
			index = zeroBytes
		}
	case "A4_HEDGED":
		rawIndex := trialBytes
		if event {
			rawIndex = zeroBytes
		}
		context := trialBytes
		if contextReset {
			context = zeroBytes
		}
		label = bytes.Join([][]byte{
			[]byte("protected-secret:" + role),
			[]byte("raw-root"), rawIndex,
			[]byte("context"), context,
		}, nil)
		index = nil
	default:
		return 0, fmt.Errorf("unknown architecture %q", r.architecture)
	}

	generated := make([]byte, 0, len(p))
	for block := uint64(0); len(generated) < len(p); block++ {
		h := sha256.New()
		h.Write([]byte("P01-GO-TLS-ROLE-RNG-V2"))
		h.Write(label)
		h.Write(index)
		h.Write(uint64Bytes(uint64(len(p))))
		h.Write(uint64Bytes(block))
		generated = append(generated, h.Sum(nil)...)
	}
	copy(p, generated[:len(p)])
	r.bytes += len(p)
	return len(p), nil
}

func (r *roleRoutedReader) stats() readerStats {
	return readerStats{
		Reads:     r.reads,
		Bytes:     r.bytes,
		ReadSizes: append([]int(nil), r.readSizes...),
		Roles:     append([]string(nil), r.roles...),
	}
}

type captureConn struct{ bytes.Buffer }

func (c *captureConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *captureConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "p01" }
func (d dummyAddr) String() string  { return string(d) }

type keyShare struct {
	MLKEM  []byte
	X25519 []byte
}

type record struct {
	SchemaVersion            string `json:"schema_version"`
	Implementation           string `json:"implementation"`
	Architecture             string `json:"architecture"`
	Recipe                   string `json:"recipe"`
	OriginComponent          string `json:"origin_component"`
	Trial                    int    `json:"trial"`
	MLKEMPublicKeySHA256     string `json:"mlkem_public_key_sha256"`
	X25519PublicKeySHA256    string `json:"x25519_public_key_sha256"`
	HybridKeyShareSHA256     string `json:"hybrid_key_share_sha256"`
	ConfigRandReads          int    `json:"config_rand_reads"`
	ConfigRandBytes          int    `json:"config_rand_bytes"`
	CryptoRandReads          int    `json:"crypto_rand_reads"`
	CryptoRandBytes          int    `json:"crypto_rand_bytes"`
	ConfigRandReadSizes      []int  `json:"config_rand_read_sizes"`
	CryptoRandReadSizes      []int  `json:"crypto_rand_read_sizes"`
	ConfigRandRoles          []string `json:"config_rand_roles"`
	ClientHelloBytes         int    `json:"client_hello_bytes"`
	ClientHelloParseAccepted bool   `json:"client_hello_parse_accepted"`
}

type cellSummary struct {
	Units        int `json:"units"`
	MLKEMUnique  int `json:"mlkem_unique"`
	X25519Unique int `json:"x25519_unique"`
	HybridUnique int `json:"hybrid_unique"`
}

type pairRecord struct {
	SchemaVersion           string `json:"schema_version"`
	Implementation          string `json:"implementation"`
	GoVersion               string `json:"go_version"`
	Architecture            string `json:"architecture"`
	Recipe                  string `json:"recipe"`
	Trial                   int    `json:"trial"`
	Anchor                  record `json:"anchor"`
	Comparison              record `json:"comparison"`
	MLKEMFreshnessPreserved bool   `json:"mlkem_freshness_preserved"`
	X25519FreshnessPreserved bool  `json:"x25519_freshness_preserved"`
	HybridFreshnessPreserved bool  `json:"hybrid_freshness_preserved"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func uint64Bytes(value uint64) []byte {
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], value)
	return out[:]
}

func readers(architecture, recipe string, trial int) (auditedReader, auditedReader) {
	config := &roleRoutedReader{architecture: architecture, recipe: recipe, trial: trial}
	global := newReader([]byte("global-crypto-rand-sham"), uint64Bytes(uint64(trial)))
	return config, global
}

func take(data []byte, offset *int, count int) ([]byte, error) {
	if count < 0 || *offset+count > len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	out := data[*offset : *offset+count]
	*offset += count
	return out, nil
}

func parseClientHello(records []byte) (keyShare, error) {
	var handshake bytes.Buffer
	for offset := 0; offset < len(records); {
		if offset+5 > len(records) {
			return keyShare{}, io.ErrUnexpectedEOF
		}
		recordType := records[offset]
		length := int(binary.BigEndian.Uint16(records[offset+3 : offset+5]))
		offset += 5
		if offset+length > len(records) {
			return keyShare{}, io.ErrUnexpectedEOF
		}
		if recordType == 22 {
			handshake.Write(records[offset : offset+length])
		}
		offset += length
	}
	data := handshake.Bytes()
	if len(data) < 4 || data[0] != 1 {
		return keyShare{}, errors.New("first handshake message is not ClientHello")
	}
	bodyLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if bodyLength+4 > len(data) {
		return keyShare{}, io.ErrUnexpectedEOF
	}
	body := data[4 : 4+bodyLength]
	offset := 0
	if _, err := take(body, &offset, 34); err != nil { // legacy_version + random
		return keyShare{}, err
	}
	sessionLenBytes, err := take(body, &offset, 1)
	if err != nil {
		return keyShare{}, err
	}
	if _, err = take(body, &offset, int(sessionLenBytes[0])); err != nil {
		return keyShare{}, err
	}
	cipherLenBytes, err := take(body, &offset, 2)
	if err != nil {
		return keyShare{}, err
	}
	if _, err = take(body, &offset, int(binary.BigEndian.Uint16(cipherLenBytes))); err != nil {
		return keyShare{}, err
	}
	compressionLenBytes, err := take(body, &offset, 1)
	if err != nil {
		return keyShare{}, err
	}
	if _, err = take(body, &offset, int(compressionLenBytes[0])); err != nil {
		return keyShare{}, err
	}
	extensionsLenBytes, err := take(body, &offset, 2)
	if err != nil {
		return keyShare{}, err
	}
	extensionsLength := int(binary.BigEndian.Uint16(extensionsLenBytes))
	extensions, err := take(body, &offset, extensionsLength)
	if err != nil {
		return keyShare{}, err
	}
	for extOffset := 0; extOffset < len(extensions); {
		header, err := take(extensions, &extOffset, 4)
		if err != nil {
			return keyShare{}, err
		}
		extType := binary.BigEndian.Uint16(header[:2])
		extData, err := take(extensions, &extOffset, int(binary.BigEndian.Uint16(header[2:])))
		if err != nil {
			return keyShare{}, err
		}
		if extType != 51 || len(extData) < 2 {
			continue
		}
		sharesLength := int(binary.BigEndian.Uint16(extData[:2]))
		if sharesLength+2 > len(extData) {
			return keyShare{}, io.ErrUnexpectedEOF
		}
		for shareOffset := 2; shareOffset < 2+sharesLength; {
			header, err := take(extData, &shareOffset, 4)
			if err != nil {
				return keyShare{}, err
			}
			group := tls.CurveID(binary.BigEndian.Uint16(header[:2]))
			share, err := take(extData, &shareOffset, int(binary.BigEndian.Uint16(header[2:])))
			if err != nil {
				return keyShare{}, err
			}
			if group == x25519MLKEM768 {
				if len(share) != mlkemPublicKeySize+x25519PublicKeySize {
					return keyShare{}, fmt.Errorf("unexpected hybrid share length %d", len(share))
				}
				return keyShare{MLKEM: append([]byte(nil), share[:mlkemPublicKeySize]...), X25519: append([]byte(nil), share[mlkemPublicKeySize:]...)}, nil
			}
		}
	}
	return keyShare{}, errors.New("X25519MLKEM768 key share not found")
}

func runUnit(architecture, recipe string, trial int) (record, error) {
	configRand, cryptoRand := readers(architecture, recipe, trial)
	originalCryptoRand := crand.Reader
	crand.Reader = cryptoRand
	defer func() { crand.Reader = originalCryptoRand }()

	conn := &captureConn{}
	client := tls.Client(conn, &tls.Config{
		ServerName:             "p01.invalid",
		InsecureSkipVerify:     true,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{x25519MLKEM768},
		Rand:                   configRand,
		SessionTicketsDisabled: true,
	})
	_ = client.Handshake() // EOF is expected after ClientHello capture.
	share, err := parseClientHello(conn.Bytes())
	if err != nil {
		return record{}, err
	}
	hybrid := append(append([]byte(nil), share.MLKEM...), share.X25519...)
	configStats := configRand.stats()
	cryptoStats := cryptoRand.stats()
	return record{
		SchemaVersion:            "1.0",
		Implementation:           "go-crypto-tls",
		Architecture:             architecture,
		Recipe:                   recipe,
		OriginComponent:          "ML-KEM-768",
		Trial:                    trial,
		MLKEMPublicKeySHA256:     digest(share.MLKEM),
		X25519PublicKeySHA256:    digest(share.X25519),
		HybridKeyShareSHA256:     digest(hybrid),
		ConfigRandReads:          configStats.Reads,
		ConfigRandBytes:          configStats.Bytes,
		CryptoRandReads:          cryptoStats.Reads,
		CryptoRandBytes:          cryptoStats.Bytes,
		ConfigRandReadSizes:      configStats.ReadSizes,
		CryptoRandReadSizes:      cryptoStats.ReadSizes,
		ConfigRandRoles:          configStats.Roles,
		ClientHelloBytes:         conn.Len(),
		ClientHelloParseAccepted: true,
	}, nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

func main() {
	outputDir := flag.String("output-dir", "evidence", "evidence output directory")
	trials := flag.Int("trials", 32, "trials per cell")
	unitArchitecture := flag.String("unit-architecture", "", "single-pair architecture")
	unitRecipe := flag.String("unit-recipe", "", "single-pair recipe")
	unitAnchor := flag.Int("unit-anchor", 0, "single-pair anchor trial")
	unitTrial := flag.Int("unit-trial", 0, "single-pair comparison trial; anchor is trial 0")
	flag.Parse()
	if *unitArchitecture != "" || *unitRecipe != "" || *unitTrial != 0 {
		if *unitArchitecture == "" || *unitRecipe == "" || *unitTrial <= 0 {
			panic("single-pair mode requires architecture, recipe and trial > 0")
		}
		anchor, err := runUnit(*unitArchitecture, *unitRecipe, *unitAnchor)
		if err != nil {
			panic(err)
		}
		comparison, err := runUnit(*unitArchitecture, *unitRecipe, *unitTrial)
		if err != nil {
			panic(err)
		}
		pair := pairRecord{
			SchemaVersion:           "1.0",
			Implementation:          "go-crypto-tls",
			GoVersion:               runtimeVersion(),
			Architecture:            *unitArchitecture,
			Recipe:                  *unitRecipe,
			Trial:                   *unitTrial,
			Anchor:                  anchor,
			Comparison:              comparison,
			MLKEMFreshnessPreserved: anchor.MLKEMPublicKeySHA256 != comparison.MLKEMPublicKeySHA256,
			X25519FreshnessPreserved: anchor.X25519PublicKeySHA256 != comparison.X25519PublicKeySHA256,
			HybridFreshnessPreserved: anchor.HybridKeyShareSHA256 != comparison.HybridKeyShareSHA256,
		}
		if err := json.NewEncoder(os.Stdout).Encode(pair); err != nil {
			panic(err)
		}
		return
	}
	if *trials < 2 {
		panic("at least two trials required")
	}
	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		panic(err)
	}
	recordPath := filepath.Join(*outputDir, "records.jsonl")
	file, err := os.Create(recordPath)
	if err != nil {
		panic(err)
	}
	encoder := json.NewEncoder(file)
	var all []record
	for _, architecture := range architectures {
		for _, recipe := range recipes {
			for trial := 0; trial < *trials; trial++ {
				record, err := runUnit(architecture, recipe, trial)
				if err != nil {
					panic(err)
				}
				if err := encoder.Encode(record); err != nil {
					panic(err)
				}
				if err := file.Sync(); err != nil {
					panic(err)
				}
				all = append(all, record)
			}
		}
	}
	if err := file.Close(); err != nil {
		panic(err)
	}

	cells := map[string]cellSummary{}
	for _, architecture := range architectures {
		for _, recipe := range recipes {
			mlkem := map[string]bool{}
			x25519 := map[string]bool{}
			hybrid := map[string]bool{}
			units := 0
			for _, item := range all {
				if item.Architecture == architecture && item.Recipe == recipe {
					units++
					mlkem[item.MLKEMPublicKeySHA256] = true
					x25519[item.X25519PublicKeySHA256] = true
					hybrid[item.HybridKeyShareSHA256] = true
				}
			}
			cells[architecture+"|"+recipe] = cellSummary{units, len(mlkem), len(x25519), len(hybrid)}
		}
	}
	keys := make([]string, 0, len(cells))
	for key := range cells {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	orderedCells := make(map[string]cellSummary, len(cells))
	for _, key := range keys {
		orderedCells[key] = cells[key]
	}
	summary := map[string]any{
		"schema_version":    "1.0",
		"scientific_status": "DEVELOPMENT_PILOT_NOT_CONFIRMATION",
		"implementation":    "Go crypto/tls X25519MLKEM768 ClientHello",
		"go_version":        fmt.Sprintf("%s", runtimeVersion()),
		"trials_per_cell":   *trials,
		"units":             len(all),
		"cells":             orderedCells,
		"limitations": []string{
			"The intervention replaces software RNG readers; it does not estimate physical-fault prevalence.",
			"The oracle is public-key-share freshness, not IND-CCA security or endpoint compromise.",
			"A4 is an RFC-8937-style prior-art baseline, not a claimed invention.",
		},
	}
	if err := writeJSON(filepath.Join(*outputDir, "summary.json"), summary); err != nil {
		panic(err)
	}
	recordsData, _ := os.ReadFile(recordPath)
	summaryData, _ := os.ReadFile(filepath.Join(*outputDir, "summary.json"))
	envelope := map[string]any{
		"schema_version": "1.0",
		"records": map[string]string{"path": "records.jsonl", "sha256": digest(recordsData)},
		"summary": map[string]string{"path": "summary.json", "sha256": digest(summaryData)},
		"status": "PASS",
	}
	if err := writeJSON(filepath.Join(*outputDir, "evidence-envelope.json"), envelope); err != nil {
		panic(err)
	}
}

func runtimeVersion() string {
	return runtime.Version()
}
