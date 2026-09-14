package netscan

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/00gxd14g/cvefeed/internal/match"
)

// Sweep is the result of examining one target, which may be one host or a
// whole range.
type Sweep struct {
	Target    string    `json:"target"`
	ScannedAt time.Time `json:"scanned_at"`
	// HostsTotal is how many addresses the target names; HostsUp is how many
	// answered on anything. The gap between them is the useful number: it says
	// how much of the range is dark rather than how much is clean.
	HostsTotal int       `json:"hosts_total"`
	HostsUp    int       `json:"hosts_up"`
	Ports      int       `json:"ports_per_host"`
	Hosts      []*Result `json:"hosts"`
	Plan       *Plan     `json:"plan,omitempty"`
	// Declined is set when the scan decided not to examine the target: auto
	// ran out of engines and the one left would have opened more connections
	// than it takes on unasked. It is a field of its own rather than something
	// read off Plan.Identification, because a declined sweep and a silent
	// target both have no hosts, and a caller telling the two apart by string
	// comparison against a note is a caller that will read "nothing answered"
	// when nothing was asked. The plan note says why and how to run it anyway.
	Declined bool `json:"declined,omitempty"`
}

// Components turns every identified service on every host into inventory.
//
// The origin carries the address as well as the port, because in a sweep
// "nginx 1.18.0 on port 80" without the host is a finding nobody can act on.
func (s *Sweep) Components() []match.Component {
	var out []match.Component
	for _, h := range s.Hosts {
		for _, svc := range h.Open {
			if !svc.Scannable() {
				continue
			}
			where := h.Addr
			if where == "" {
				where = h.Host
			}
			out = append(out, match.Component{
				Name:    svc.Product,
				Version: svc.Version,
				Vendor:  svc.Vendor,
				CPE:     svc.CPE(),
				Origin:  "netscan:" + where + ":" + itoa(svc.Port),
			})
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// workers runs fn over every job produce yields, on at most n goroutines.
//
// The goroutines are started first and the jobs are handed to them, rather
// than one goroutine started per job that then waits for a slot. The second
// shape looks bounded — only n of them ever run — but every one of them exists
// from the moment the loop passes it, and a goroutine is a few kilobytes of
// stack before it has done anything: "-ports all" against one host was 65,535
// of them, and a /16 was one per address plus one per port of every address
// in flight, before a /8 is even considered. The producer is therefore the
// side that blocks, and it is the producer that watches the context, so a
// cancelled scan stops handing out work instead of draining a queue nobody
// will read.
func workers[T any](ctx context.Context, n int, produce func(yield func(T) bool), fn func(T)) {
	if n < 1 {
		n = 1
	}
	jobs := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				fn(job)
			}
		}()
	}
	produce(func(job T) bool {
		if ctx.Err() != nil {
			return false
		}
		select {
		case jobs <- job:
			return true
		case <-ctx.Done():
			return false
		}
	})
	close(jobs)
	wg.Wait()
}

// sweepBuiltin walks a range with the built-in prober.
//
// It exists so a range can be scanned with nothing installed, but it is the
// slow path by a wide margin and says so: one TCP connection per address per
// port, where masscan sends one packet and waits for nobody.
func (s *Scanner) sweepBuiltin(ctx context.Context, tg *Targets, ports []int) ([]*Result, error) {
	var (
		mu    sync.Mutex
		hosts []*Result
		fail  error
	)
	// Targets.Each is already the lazy producer this needs: it walks the
	// range one address at a time and stops when told, so a /8 is never
	// expanded and a cancelled sweep stops at the next address.
	workers(ctx, min(s.hostConcurrency(), tg.Len()), tg.Each, func(ip string) {
		res, err := s.Scan(ctx, ip, ports)
		if err != nil {
			mu.Lock()
			if fail == nil {
				fail = err
			}
			mu.Unlock()
			return
		}
		if len(res.Open) == 0 && len(res.Unidentified) == 0 {
			return // nothing answered; not a host worth reporting
		}
		mu.Lock()
		hosts = append(hosts, res)
		mu.Unlock()
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if fail != nil {
		return nil, fail
	}
	sortHosts(hosts)
	return hosts, nil
}

// hostConcurrency bounds how many addresses are in flight at once. It is
// separate from the per-host port concurrency, and their product is what the
// network actually sees.
func (s *Scanner) hostConcurrency() int {
	if s.opt.HostConcurrency > 0 {
		return s.opt.HostConcurrency
	}
	return 16
}

func sortHosts(hosts []*Result) {
	sort.Slice(hosts, func(i, j int) bool {
		a, b := hosts[i].Addr, hosts[j].Addr
		if a == "" {
			a = hosts[i].Host
		}
		if b == "" {
			b = hosts[j].Host
		}
		return a < b
	})
}
