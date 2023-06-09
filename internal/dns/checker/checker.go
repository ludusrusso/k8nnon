package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	corev1alpha1 "github.com/kannon-email/k8nnon/api/v1alpha1"
	"github.com/kannon-email/k8nnon/internal/dns/resolver"
)

type DNSChecker struct {
	resolvers []resolver.Resolver
}

var ServerAddresses = []string{
	"8.8.8.8",
	// "8.8.4.4",
	// "9.9.9.9",
	"149.112.112.112",
	"208.67.222.222",
	"208.67.220.220",
	// "1.1.1.1",
	"1.0.0.1",
	"8.26.56.26",
	"8.20.247.20",
}

type DNSCheckStats struct {
	CntOK  int
	CntKO  int
	CntErr int
}

func (c DNSCheckStats) Result() bool {
	return c.CntOK > c.CntKO+c.CntErr
}

func NewDNSChecker(r ...resolver.Resolver) *DNSChecker {
	return &DNSChecker{resolvers: r}
}

type checkFunc func(ctx context.Context, r resolver.Resolver, domain *corev1alpha1.Domain) (bool, error)

func (d DNSChecker) CheckDomainDKim(ctx context.Context, domain *corev1alpha1.Domain) DNSCheckStats {
	return d.checkDNS(ctx, domain, checkDomainDKim)
}

func (d DNSChecker) CheckDomainSPF(ctx context.Context, domain *corev1alpha1.Domain) DNSCheckStats {
	return d.checkDNS(ctx, domain, checkDomainSPF)
}

func (d DNSChecker) CheckDomainStatsDNS(ctx context.Context, domain *corev1alpha1.Domain) DNSCheckStats {
	return d.checkDNS(ctx, domain, checkDomainStatsDNS)
}

func (d DNSChecker) checkDNS(ctx context.Context, domain *corev1alpha1.Domain, checkFunc checkFunc) DNSCheckStats {
	result := DNSCheckStats{}

	wg := sync.WaitGroup{}
	m := sync.Mutex{}

	innertCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, res := range d.resolvers {
		wg.Add(1)

		go func(r resolver.Resolver) {
			defer wg.Done()

			status, err := checkFunc(innertCtx, r, domain)
			m.Lock()
			if err != nil {
				result.CntErr += 1
			}
			if status {
				result.CntOK += 1
			} else {
				result.CntKO += 1
			}
			m.Unlock()
		}(res)
	}

	wg.Wait()

	return result
}

func checkDomainDKim(ctx context.Context, r resolver.Resolver, domain *corev1alpha1.Domain) (bool, error) {
	sub := fmt.Sprintf("%s._domainkey.%s", domain.Spec.DKim.Selector, domain.Spec.DomainName)

	res, err := r.LookupTXT(ctx, sub)
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

func checkDomainSPF(ctx context.Context, r resolver.Resolver, domain *corev1alpha1.Domain) (bool, error) {
	res, err := r.LookupTXT(ctx, domain.Spec.DomainName)
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

func checkDomainStatsDNS(ctx context.Context, r resolver.Resolver, domain *corev1alpha1.Domain) (bool, error) {
	statsDomain := fmt.Sprintf("%s.%s", domain.Spec.StatsPrefix, domain.Spec.DomainName)

	res, err := r.LookupCNAME(ctx, statsDomain)
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
