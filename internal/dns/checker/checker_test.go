package checker_test

import (
	"context"
	"testing"

	mockdns "github.com/foxcpp/go-mockdns"
	"github.com/stretchr/testify/assert"

	corev1alpha1 "github.com/kannon-email/k8nnon/api/v1alpha1"
	"github.com/kannon-email/k8nnon/internal/dns/checker"
	"github.com/kannon-email/k8nnon/internal/dns/resolver"
)

func TestDKimNotOk(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"selector._domainkey.example.com.": {
				TXT: []string{
					"k=rsa; p=wrongKey",
				},
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainDKim(ctx, domain)
	assert.False(t, res.Result(), "should not have resolved DKIM")
}

func TestDKimOk(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"selector._domainkey.example.com.": {
				TXT: []string{
					"k=rsa; p=publicKey",
				},
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainDKim(ctx, domain)
	assert.True(t, res.Result(), "should have resolved DKIM")
}

func TestDKimMultipleOK(t *testing.T) {
	ctx := createContext(t)

	r := []resolver.Resolver{
		&mockdns.Resolver{
			Zones: map[string]mockdns.Zone{
				"selector._domainkey.example.com.": {
					TXT: []string{
						"k=rsa; p=publicKey",
					},
				},
			},
		},
		&mockdns.Resolver{
			Zones: map[string]mockdns.Zone{
				"selector._domainkey.example.com.": {
					TXT: []string{
						"k=rsa; p=publicKey",
					},
				},
			},
		},
		&mockdns.Resolver{
			Zones: map[string]mockdns.Zone{
				"selector._domainkey.example.com.": {
					TXT: []string{
						"k=rsa; p=publicKeyErr",
					},
				},
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(r...)

	res := c.CheckDomainDKim(ctx, domain)
	assert.True(t, res.Result(), "should have resolved DKIM")
	assert.Equal(t, 2, res.CntOK)
	assert.Equal(t, 1, res.CntKO)
}

func TestDKimMultipleKO(t *testing.T) {
	ctx := createContext(t)

	r := []resolver.Resolver{
		&mockdns.Resolver{
			Zones: map[string]mockdns.Zone{
				"selector._domainkey.example.com.": {
					TXT: []string{
						"k=rsa; p=publicKey",
					},
				},
			},
		},
		&mockdns.Resolver{
			Zones: map[string]mockdns.Zone{},
		},
		&mockdns.Resolver{
			Zones: map[string]mockdns.Zone{
				"selector._domainkey.example.com.": {
					TXT: []string{
						"k=rsa; p=publicKeyErr",
					},
				},
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(r...)

	res := c.CheckDomainDKim(ctx, domain)
	assert.False(t, res.Result(), "should have resolved DKIM")
	assert.Equal(t, 2, res.CntKO)
	assert.Equal(t, 1, res.CntOK)
}

func TestDKIMWithoutHost(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{}

	domain := createDomain(t)
	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainDKim(ctx, domain)
	assert.False(t, res.Result(), "should not have resolved SPF")
}

func TestSPFNotOk(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"example.com.": {
				TXT: []string{
					"v=spf1 include:mx.other.com ~all",
				},
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainSPF(ctx, domain)
	assert.False(t, res.Result(), "should not have resolved SPF")
}

func TestSPFOk(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"example.com.": {
				TXT: []string{
					"v=spf1 include:mx.example.com ~all",
				},
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainSPF(ctx, domain)
	assert.True(t, res.Result(), "should have resolved SPF")
}

func TestStatsWithoutHost(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{}

	domain := createDomain(t)
	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainStatsDNS(ctx, domain)
	assert.False(t, res.Result(), "should not have resolved CNAME")
}

func TestStatsNotOk(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"stats.example.com": {
				CNAME: "mx.fake.com",
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainStatsDNS(ctx, domain)
	assert.False(t, res.Result(), "should not have resolved CANME")
}

func TestStatsOk(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"stats.example.com": {
				CNAME: "mx.example.com",
			},
		},
	}

	domain := createDomain(t)

	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainStatsDNS(ctx, domain)
	assert.True(t, res.Result(), "should have resolved CNAME")
}

func TestSPFNWithoutHost(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{}

	domain := createDomain(t)
	c := checker.NewDNSChecker(&r)

	res := c.CheckDomainSPF(ctx, domain)
	assert.False(t, res.Result(), "should not have resolved SPF")
}

func TestLoopupCname(t *testing.T) {
	ctx := createContext(t)

	r := mockdns.Resolver{
		Zones: map[string]mockdns.Zone{
			"stats.example.com": {
				CNAME: "mx.example.com",
			},
		},
	}

	res, err := r.LookupCNAME(ctx, "stats.example.com")
	assert.Nil(t, err)
	assert.Equal(t, "mx.example.com", res, "should have resolved CNAME")

}

func createDomain(t *testing.T) *corev1alpha1.Domain {
	t.Helper()

	return &corev1alpha1.Domain{
		Spec: corev1alpha1.DomainSpec{
			DomainName: "example.com",
			DKim: corev1alpha1.DKim{
				Selector:  "selector",
				PublicKey: "publicKey",
			},
			BaseDomain:  "mx.example.com",
			StatsPrefix: "stats",
		},
	}
}

func createContext(t *testing.T) context.Context {
	t.Helper()

	return context.Background()
}
