package resolver

import (
	"context"
	"net"
	"time"
)

type Resolver interface {
	// LookupAddr(addr string) (names []string, err error)
	LookupCNAME(ctx context.Context, name string) (cname string, err error)
	// LookupHost(host string) (addrs []string, err error)
	// LookupIP(host string) (ips []net.IP, err error)
	// LookupMX(name string) (mxs []*net.MX, err error)
	// LookupNS(name string) (nss []*net.NS, err error)
	// LookupPort(network, service string) (port int, err error)
	// LookupSRV(service, proto, name string) (cname string, addrs []*net.SRV, err error)
	LookupTXT(ctx context.Context, name string) (txts []string, err error)
}

func NewResolvers(address ...string) []Resolver {
	resolvers := make([]Resolver, 0, len(address))
	for _, addr := range address {
		resolvers = append(resolvers, newResolver(addr))
	}

	return resolvers
}

func newResolver(address string) Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, "udp", address+":53")
		},
	}
}
