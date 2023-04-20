package checker

import (
	"context"
	"fmt"
	"net"
	"strings"

	corev1alpha1 "github.com/kannon-email/k8nnon/api/v1alpha1"
)

type DNSChecker struct {
	r Resolver
}

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

func NewDNSChecker(r Resolver) *DNSChecker {
	return &DNSChecker{r: r}
}

func (d DNSChecker) CheckDomainDKim(ctx context.Context, domain *corev1alpha1.Domain) (bool, error) {
	sub := fmt.Sprintf("%s._domainkey.%s", domain.Spec.DKim.Selector, domain.Spec.DomainName)

	res, err := d.r.LookupTXT(ctx, sub)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return false, nil
			}
		}

		return false, err
	}

	for _, txt := range res {
		if txt == fmt.Sprintf("k=rsa; p=%s", domain.Spec.DKim.PublicKey) {
			return true, nil
		}
	}

	return false, nil
}

func (d DNSChecker) CheckDomainSPF(ctx context.Context, domain *corev1alpha1.Domain) (bool, error) {
	res, err := d.r.LookupTXT(ctx, domain.Spec.DomainName)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return false, nil
			}
		}

		return false, err
	}

	for _, txt := range res {
		if strings.Contains(txt, fmt.Sprintf("include:%s", domain.Spec.BaseDomain)) {
			return true, nil
		}
	}

	return false, nil
}

func (d DNSChecker) CheckDomainStatsDNS(ctx context.Context, domain *corev1alpha1.Domain) (bool, error) {
	statsDomain := fmt.Sprintf("%s.%s", domain.Spec.StatsPrefix, domain.Spec.DomainName)

	res, err := d.r.LookupCNAME(ctx, statsDomain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			if dnsErr.IsNotFound {
				return false, nil
			}
		}

		return false, err
	}

	return res == domain.Spec.BaseDomain || res == domain.Spec.BaseDomain+".", nil
}
