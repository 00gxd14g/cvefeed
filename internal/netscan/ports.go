package netscan

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// defaultTopN is how many ports a scan looks at when the caller names none.
//
// nmap's frequency data covers about 93% of open ports in this many, and it
// takes about half a minute against one host. "all" is available and takes four
// times as long; the report says so, because a scan that quietly looked at 1000
// of 65535 ports and found nothing is not the same as a clean host.
//
// A full 65,535-port sweep is a different operation with a different cost and
// a different footprint on the network, and it should be something an operator
// asks for rather than something they get by accident.
const defaultTopN = 1000

// DefaultPorts returns the ports a scan looks at when none are named: the
// thousand most commonly open, by nmap's frequency data. That data is read from
// nmap-services where nmap is installed and is compiled in where it is not, so
// the default is the same breadth on every machine. The 65-port hand-written
// list this replaced found 4 open ports on a real host where a full scan found
// 23, and it was the fallback on every machine without nmap.
func DefaultPorts() []int { return TopPorts(defaultTopN) }

// ParsePorts reads a port specification.
//
// Comma separated numbers and ranges — "22,80,443,8000-8100" — plus two words:
// "all" for every port, and "top:N" for the N most commonly open, which is what
// nmap's frequency data says rather than what anyone remembers.
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, errors.New("netscan: no ports given")
	}
	if strings.EqualFold(spec, "all") {
		out := make([]int, 65535)
		for i := range out {
			out[i] = i + 1
		}
		return out, nil
	}
	if rest, ok := strings.CutPrefix(strings.ToLower(spec), "top:"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("netscan: %q is not a count of ports", spec)
		}
		return TopPorts(n), nil
	}
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("netscan: empty entry in port list")
		}
		lo, hi, err := parseRange(part)
		if err != nil {
			return nil, err
		}
		for p := lo; p <= hi; p++ {
			seen[p] = true
		}
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func parseRange(part string) (int, int, error) {
	if lo, hi, ok := strings.Cut(part, "-"); ok {
		a, err := parsePort(lo)
		if err != nil {
			return 0, 0, err
		}
		b, err := parsePort(hi)
		if err != nil {
			return 0, 0, err
		}
		if a > b {
			return 0, 0, fmt.Errorf("netscan: port range %q runs backwards", part)
		}
		return a, b, nil
	}
	p, err := parsePort(part)
	return p, p, err
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("netscan: %q is not a port number", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("netscan: port %d is out of range", p)
	}
	return p, nil
}
