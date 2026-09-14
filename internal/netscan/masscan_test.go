package netscan

import "testing"

// Real `masscan -oJ -` output. The format is a JSON array whose elements are
// separated by leading commas on their own lines, one object per host-port.
const masscanJSON = `[
{   "ip": "172.19.0.4",   "timestamp": "1787235110", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
,
{   "ip": "172.19.0.4",   "timestamp": "1787235110", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 64} ] }
]
`

func TestMasscanJSONYieldsTheOpenPorts(t *testing.T) {
	got, err := parseMasscanJSON([]byte(masscanJSON))
	if err != nil {
		t.Fatalf("parseMasscanJSON: %v", err)
	}
	if len(got) != 2 || got[0] != 80 || got[1] != 443 {
		t.Fatalf("ports = %v, want [80 443] sorted", got)
	}
}

func TestMasscanEmptyOutputIsNotAnError(t *testing.T) {
	for _, in := range []string{"", "[\n]", "[]"} {
		got, err := parseMasscanJSON([]byte(in))
		if err != nil {
			t.Errorf("parseMasscanJSON(%q) = %v; a host with nothing open is a result, not a failure", in, err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want none", got)
		}
	}
}

func TestMasscanIgnoresPortsThatAreNotOpen(t *testing.T) {
	const in = `[
{ "ip": "10.0.0.1", "ports": [ {"port": 22, "proto": "tcp", "status": "closed"} ] }
,
{ "ip": "10.0.0.1", "ports": [ {"port": 80, "proto": "tcp", "status": "open"} ] }
]`
	got, err := parseMasscanJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 80 {
		t.Fatalf("ports = %v, want only the open one", got)
	}
}

// masscan writes its progress to stderr as it goes, which is the only real
// measurement available during a sweep large enough to need it.
func TestMasscanProgressIsReadFromItsOutput(t *testing.T) {
	cases := map[string]float64{
		"rate: 12.34-kpps, 43.21% done, waiting 0-secs, found=7":  43.21,
		"rate:  0.00-kpps, 100.00% done, waiting 5-secs, found=0": 100,
		"Starting masscan 1.3.2":                                  -1,
		"":                                                        -1,
	}
	for line, want := range cases {
		got, ok := masscanPercent(line)
		if want < 0 {
			if ok {
				t.Errorf("masscanPercent(%q) read %v from a line with no percentage", line, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("masscanPercent(%q) = %v, %v; want %v", line, got, ok, want)
		}
	}
}
