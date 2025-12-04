// pwfz.go
//
// Usage:
//   PASSWORK_API_KEY=... pwfz [search query...]
//
// Workflow:
//   1. Login with /auth/login/{apiKey} -> token
//   2. POST /passwords/search {query}  -> list of ids
//   3. For each id: GET /passwords/{id}
//   4. Show in fzf: name | path | login | url | description
//   5. Copy cryptedPassword of selected entry to clipboard.
//
// Env:
//   PASSWORK_BASE_URL   (required)
//   PASSWORK_API_KEY    (required)
//   FZF_BIN             (default: fzf)
//   CLIP_BIN            (optional; pbcopy/xclip/wl-copy autodetected)

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// Config & types
// -----------------------------------------------------------------------------

type Config struct {
	BaseURL string
	APIKey  string
}

type loginResponse struct {
	Status string `json:"status"`
	Data   struct {
		Token string `json:"token"`
	} `json:"data"`
}

// /passwords/search response (short items)
type passwordSearchResponse struct {
	Status string              `json:"status"`
	Data   []passwordSearchHit `json:"data"`
}

type passwordSearchHit struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// /passwords/{id} response (full item)
type passwordGetResponse struct {
	Status string         `json:"status"`
	Data   passwordDetail `json:"data"`
}

type passwordDetail struct {
	VaultID         string           `json:"vaultId"`
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Login           string           `json:"login"`
	URL             string           `json:"url"`
	CryptedPassword string           `json:"cryptedPassword"`
	Tags            []string         `json:"tags"`
	Color           int              `json:"color"`
	Path            []pathSegment    `json:"path"`
	Custom          []customField    `json:"custom"`
	Attachments     []attachmentInfo `json:"attachments"`
}

type pathSegment struct {
	Order int    `json:"order"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	ID    string `json:"id"`
}

type customField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type attachmentInfo struct {
	Name         string `json:"name"`
	ID           string `json:"id"`
	EncryptedKey string `json:"encryptedKey"`
}

// -----------------------------------------------------------------------------
// HTTP helpers
// -----------------------------------------------------------------------------

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
	}
}

func login(ctx context.Context, cfg Config, client *http.Client) (string, error) {
	if cfg.APIKey == "" {
		return "", errors.New("PASSWORK_API_KEY is not set")
	}
	url := strings.TrimRight(cfg.BaseURL, "/") + "/auth/login/" + cfg.APIKey

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("login failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var lr loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", err
	}
	if lr.Status != "success" || lr.Data.Token == "" {
		return "", fmt.Errorf("login failed: status=%s token empty", lr.Status)
	}
	return lr.Data.Token, nil
}

func searchPasswords(ctx context.Context, cfg Config, client *http.Client, token, query string) ([]passwordSearchHit, error) {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/passwords/search"

	reqBody := map[string]string{"query": query}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Passwork-Auth", token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("search failed: status=%d body=%s", resp.StatusCode, string(body))
	}

	var sr passwordSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, err
	}
	if sr.Status != "success" {
		return nil, fmt.Errorf("search failed: status=%s", sr.Status)
	}
	return sr.Data, nil
}

func getPassword(ctx context.Context, cfg Config, client *http.Client, token, id string) (passwordDetail, error) {
	url := strings.TrimRight(cfg.BaseURL, "/") + "/passwords/" + id

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return passwordDetail{}, err
	}
	req.Header.Set("Passwork-Auth", token)

	resp, err := client.Do(req)
	if err != nil {
		return passwordDetail{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return passwordDetail{}, fmt.Errorf("get password %s failed: status=%d body=%s", id, resp.StatusCode, string(body))
	}

	var gr passwordGetResponse
	if err := json.NewDecoder(resp.Body).Decode(&gr); err != nil {
		return passwordDetail{}, err
	}
	if gr.Status != "success" {
		return passwordDetail{}, fmt.Errorf("get password %s failed: status=%s", id, gr.Status)
	}
	return gr.Data, nil
}

// -----------------------------------------------------------------------------
// fzf & clipboard helpers
// -----------------------------------------------------------------------------

func runFzf(lines []string) (string, error) {
	fzf := os.Getenv("FZF_BIN")
	if fzf == "" {
		fzf = "fzf"
	}

	cmd := exec.Command(fzf, "--with-nth=2..", "--height=15", "--style=minimal", "--color=dark", "--delimiter=\t")
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n"))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.String()), nil
}

func detectClipboardCommand() []string {
	if bin := os.Getenv("CLIP_BIN"); bin != "" {
		return []string{bin}
	}
	switch runtime.GOOS {
	case "darwin":
		return []string{"pbcopy"}
	case "linux":
		if _, err := exec.LookPath("wl-copy"); err == nil {
			return []string{"wl-copy"}
		}
		if _, err := exec.LookPath("xclip"); err == nil {
			return []string{"xclip", "-selection", "clipboard"}
		}
	}
	return nil
}

func copyToClipboard(text string) error {
	cmdArgs := detectClipboardCommand()
	if cmdArgs == nil {
		return errors.New("no clipboard command found (set CLIP_BIN or install pbcopy/xclip/wl-copy)")
	}
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = strings.NewReader(text)
	return cmd.Run()
}

// -----------------------------------------------------------------------------
// formatting helpers
// -----------------------------------------------------------------------------

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func orEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return s
}

func decodeB64OrRaw(s string) string {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return s
	}
	return string(b)
}

func formatDescription(custom []customField) string {
	if len(custom) == 0 {
		return ""
	}
	parts := make([]string, 0, len(custom))
	for _, c := range custom {
		name := strings.TrimSpace(decodeB64OrRaw(c.Name))
		val := strings.TrimSpace(decodeB64OrRaw(c.Value))
		if name == "" && val == "" {
			continue
		}
		if name == "" {
			parts = append(parts, val)
		} else if val == "" {
			parts = append(parts, name)
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", name, val))
		}
	}
	return strings.Join(parts, "; ")
}

func formatPath(path []pathSegment) string {
	if len(path) == 0 {
		return "-"
	}
	// sort by order just in case
	sort.Slice(path, func(i, j int) bool {
		return path[i].Order < path[j].Order
	})
	names := make([]string, 0, len(path))
	for _, p := range path {
		if p.Name != "" {
			names = append(names, p.Name)
		}
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, " / ")
}

func buildFzfLine(p passwordDetail) string {
	name := p.Name
	if name == "" {
		name = "(no title)"
	}
	pathStr := formatPath(p.Path)
	desc := formatDescription(p.Custom)

	// Column 1: ID (hidden by --with-nth=2..)
	// Column 2..: user-visible data.
	display := fmt.Sprintf("%s | %s | %s | %s | %s",
		name,
		pathStr,
		orEmpty(p.Login),
		orEmpty(p.URL),
		desc,
	)

	return fmt.Sprintf("%s\t%s", p.ID, display)
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------

func main() {
	query := ""
	if len(os.Args) > 1 {
		query = strings.Join(os.Args[1:], " ")
	}

	cfg := Config{
		BaseURL: os.Getenv("PASSWORK_BASE_URL"),
		APIKey:  os.Getenv("PASSWORK_API_KEY"),
	}
	if cfg.BaseURL == "" {
		fmt.Fprintln(os.Stderr, "PASSWORK_BASE_URL environment variable is not set")
		os.Exit(1)
	}

	ctx := context.Background()
	client := newHTTPClient()

	token, err := login(ctx, cfg, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "login error: %v\n", err)
		os.Exit(1)
	}

	hits, err := searchPasswords(ctx, cfg, client, token, query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "search error: %v\n", err)
		os.Exit(1)
	}
	if len(hits) == 0 {
		fmt.Fprintf(os.Stderr, "no passwords found for query %q\n", query)
		return
	}

	// Fetch full details for each id
	details := make([]passwordDetail, 0, len(hits))
	for _, h := range hits {
		d, err := getPassword(ctx, cfg, client, token, h.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skip %s: %v\n", h.ID, err)
			continue
		}
		details = append(details, d)
	}
	if len(details) == 0 {
		fmt.Fprintf(os.Stderr, "no usable password entries\n")
		return
	}

	lines := make([]string, 0, len(details))
	for _, d := range details {
		lines = append(lines, buildFzfLine(d))
	}

	selected, err := runFzf(lines)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fzf error: %v\n", err)
		os.Exit(1)
	}
	if selected == "" {
		return
	}

	// first field (before \t) is id
	id := strings.SplitN(selected, "\t", 2)[0]

	var chosen *passwordDetail
	for i := range details {
		if details[i].ID == id {
			chosen = &details[i]
			break
		}
	}
	if chosen == nil {
		fmt.Fprintf(os.Stderr, "could not find password for selected id %s\n", id)
		os.Exit(1)
	}

	if chosen.CryptedPassword == "" {
		fmt.Fprintf(os.Stderr, "selected entry has empty cryptedPassword\n")
		os.Exit(1)
	}

	// cryptedPassword is base64-encoded – decode before copying
	raw := chosen.CryptedPassword
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// If decoding fails for some reason, fall back to raw value
		fmt.Fprintf(os.Stderr, "warning: cannot base64-decode cryptedPassword, copying raw value: %v\n", err)
	} else {
		raw = string(decoded)
	}

	if err := copyToClipboard(raw); err != nil {
		fmt.Fprintf(os.Stderr, "clipboard error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Copied password for %q to clipboard.\n", chosen.Name)
}
