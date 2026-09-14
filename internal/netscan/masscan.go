package netscan

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// HasMasscan reports whether masscan is on PATH.
func HasMasscan() bool { _, err := exec.LookPath("masscan"); return err == nil }

// masscanHost is one line of `masscan -oJ` output.
type masscanHost struct {
	IP    string `json:"ip"`
	Ports []struct {
		Port   int    `json:"port"`
		Proto  string `json:"proto"`
		Status string `json:"status"`
	} `json:"ports"`
}

// parseMasscanJSON reads masscan's JSON and returns the open TCP ports.
//
// Only "open" is taken. masscan is a discovery pass whose job is to narrow the
// range something slower has to look at, and it is optimistic by design: at
// speed it reports ports as open that a full handshake finds closed. Passing its
// answers through unconfirmed would put ports nothing is listening on into a
// report about what is running, which is why nmap re-tests every one of them.
func parseMasscanJSON(b []byte) ([]int, error) {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, nil
	}
	var hosts []masscanHost
	if err := json.Unmarshal([]byte(s), &hosts); err != nil {
		return nil, fmt.Errorf("netscan: parse masscan json: %w", err)
	}
	seen := map[int]bool{}
	for _, h := range hosts {
		for _, p := range h.Ports {
			if p.Status == "open" && (p.Proto == "" || p.Proto == "tcp") {
				seen[p.Port] = true
			}
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// parseMasscanHosts groups masscan's findings by address.
//
// A sweep needs to know which ports are open on which host, not merely that
// something somewhere answered: giving nmap the union of every port seen across
// a /16 would re-probe thousands of closed ports on every address.
func parseMasscanHosts(b []byte) (map[string][]int, error) {
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, nil
	}
	var hosts []masscanHost
	if err := json.Unmarshal([]byte(s), &hosts); err != nil {
		return nil, fmt.Errorf("netscan: parse masscan json: %w", err)
	}
	seen := map[string]map[int]bool{}
	for _, h := range hosts {
		if h.IP == "" {
			continue
		}
		for _, p := range h.Ports {
			if p.Status != "open" || (p.Proto != "" && p.Proto != "tcp") {
				continue
			}
			if seen[h.IP] == nil {
				seen[h.IP] = map[int]bool{}
			}
			seen[h.IP][p.Port] = true
		}
	}
	out := make(map[string][]int, len(seen))
	for ip, ports := range seen {
		list := make([]int, 0, len(ports))
		for p := range ports {
			list = append(list, p)
		}
		sort.Ints(list)
		out[ip] = list
	}
	return out, nil
}

// masscanPercent reads the completion figure masscan writes to stderr while it
// runs. That line is the only real measurement of a sweep's progress: nothing
// else in the pipeline knows how far through a /16 it is.
func masscanPercent(line string) (float64, bool) {
	i := strings.Index(line, "% done")
	if i < 0 {
		return 0, false
	}
	// Walk back over the number.
	j := i
	for j > 0 {
		c := line[j-1]
		if (c >= '0' && c <= '9') || c == '.' {
			j--
			continue
		}
		break
	}
	if j == i {
		return 0, false
	}
	v, err := strconv.ParseFloat(line[j:i], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
