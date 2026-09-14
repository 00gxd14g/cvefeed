package netscan

import (
	"fmt"
	"math/big"
	"net/netip"
	"strings"
)

// Targets is a set of hosts to examine: one address, or a CIDR block.
//
// It is never expanded into a list. A /8 is 16,777,214 addresses and building
// that slice costs hundreds of megabytes before a single packet moves, so the
// set is described by its prefix and walked one address at a time.
type Targets struct {
	spec   string
	prefix netip.Prefix
	single netip.Addr // set when the target was a bare address
}

// ParseTargets reads a host, an address, or a CIDR block.
func ParseTargets(spec string) (*Targets, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("netscan: no target given")
	}
	if strings.Contains(spec, "/") {
		p, err := netip.ParsePrefix(spec)
		if err != nil {
			return nil, fmt.Errorf("netscan: %q is not a CIDR block: %w", spec, err)
		}
		return &Targets{spec: spec, prefix: p.Masked()}, nil
	}
	if err := validateTarget(spec); err != nil {
		return nil, err
	}
	if addr, err := netip.ParseAddr(spec); err == nil {
		return &Targets{spec: spec, single: addr}, nil
	}
	// A hostname. It resolves at connect time, and there is exactly one of it.
	return &Targets{spec: spec}, nil
}

// Spec returns the target as written, so it can be handed to a tool that
// understands CIDR itself rather than expanded into an argument list.
func (t *Targets) Spec() string { return t.spec }

// IsRange reports whether this names more than one address.
func (t *Targets) IsRange() bool { return t.prefix.IsValid() && t.Len() > 1 }

// Len is how many addresses will be examined.
//
// The network and broadcast addresses of an IPv4 block are excluded, because
// nothing answers on them — except in a /31 or /32, where RFC 3021 gives both
// addresses to hosts. Anything wider than a /8 is reported saturated rather
// than as a number that would not fit: the caller is going to refuse it anyway.
func (t *Targets) Len() int {
	if !t.prefix.IsValid() {
		return 1
	}
	bits := t.prefix.Addr().BitLen() - t.prefix.Bits()
	if bits > 40 {
		return maxInt
	}
	total := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	if t.prefix.Addr().Is4() && bits >= 2 {
		total.Sub(total, big.NewInt(2)) // network and broadcast
	}
	if !total.IsInt64() || total.Int64() > int64(maxInt) {
		return maxInt
	}
	return int(total.Int64())
}

const maxInt = int(^uint(0) >> 1)

// String describes the target for a human, which for a range means saying how
// big it is before anyone starts it.
func (t *Targets) String() string {
	if !t.IsRange() {
		return t.spec
	}
	return fmt.Sprintf("%s (%d hosts)", t.spec, t.Len())
}

// Each walks the addresses, stopping early if fn returns false.
//
// Laziness is the point: the caller may be crossing a /8 and deciding to stop
// after the first few thousand, and materialising the range to find that out
// would be the expensive part.
func (t *Targets) Each(fn func(ip string) bool) {
	if !t.prefix.IsValid() {
		if t.single.IsValid() {
			fn(t.single.String())
			return
		}
		fn(t.spec) // a hostname
		return
	}

	addr := t.prefix.Addr()
	skipEdges := addr.Is4() && t.prefix.Bits() <= 30
	if skipEdges {
		addr = addr.Next() // past the network address
	}
	for t.prefix.Contains(addr) {
		if skipEdges && isBroadcast(t.prefix, addr) {
			return
		}
		if !fn(addr.String()) {
			return
		}
		next := addr.Next()
		if !next.IsValid() {
			return
		}
		addr = next
	}
}

// isBroadcast reports whether addr is the all-ones address of its prefix.
func isBroadcast(p netip.Prefix, addr netip.Addr) bool {
	b := addr.As16()
	// Set every host bit and compare: the broadcast address is the one where
	// doing so changes nothing.
	host := p.Addr().BitLen() - p.Bits()
	full := addr.AsSlice()
	for i := len(full) - 1; i >= 0 && host > 0; i-- {
		n := host
		if n > 8 {
			n = 8
		}
		full[i] |= byte(0xff >> (8 - n))
		host -= n
	}
	other, ok := netip.AddrFromSlice(full)
	if !ok {
		return false
	}
	_ = b
	return other == addr
}
