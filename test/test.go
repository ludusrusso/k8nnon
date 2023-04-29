package main

import (
	"context"
	"fmt"

	"github.com/kannon-email/k8nnon/api/v1alpha1"
	"github.com/kannon-email/k8nnon/internal/dns/checker"
	"github.com/kannon-email/k8nnon/internal/dns/resolver"
)

func main() {
	resolvers := resolver.NewResolvers(checker.ServerAddresses...)
	c := checker.NewDNSChecker(resolvers...)

	res, err := c.CheckDomainStatsDNS(context.Background(), &v1alpha1.Domain{
		Spec: v1alpha1.DomainSpec{
			DomainName:  "kd.ludusrusso.dev",
			BaseDomain:  "kannon.ludusrusso.dev",
			StatsPrefix: "stats",
		},
	})

	fmt.Printf("%v %v", res, err)
}
