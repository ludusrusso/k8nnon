/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"reflect"
	"time"

	netwrkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
	"github.com/kannon-email/k8nnon/api/v1alpha1"
	corev1alpha1 "github.com/kannon-email/k8nnon/api/v1alpha1"
	"github.com/kannon-email/k8nnon/internal/dns/checker"
)

// DomainReconciler reconciles a Domain object
type DomainReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	DNSChecker checker.DNSChecker
}

//+kubebuilder:rbac:groups=core.k8s.kannon.email,resources=domains,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core.k8s.kannon.email,resources=domains/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core.k8s.kannon.email,resources=domains/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Domain object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *DomainReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	l.Info("reconciling domain", "domain", req.NamespacedName)

	domain := &corev1alpha1.Domain{}
	if err := r.Get(ctx, req.NamespacedName, domain); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	dnsStatus, err := r.checkDomainDNS(ctx, l, domain)
	if err != nil {
		return ctrl.Result{RequeueAfter: 1 * time.Minute}, err
	}

	domain.Status = corev1alpha1.DomainStatus{
		DNS: dnsStatus,
	}

	if err := r.reconcileIngress(ctx, domain, l); err != nil {
		l.Error(err, "failed to reconcile ingress", "domain", domain)
		return ctrl.Result{}, err
	}

	if err := r.Status().Update(ctx, domain); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: computeReconcileInterval(domain),
	}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *DomainReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha1.Domain{}).
		Owns(&netwrkingv1.Ingress{}).
		Complete(r)
}

func (r *DomainReconciler) reconcileIngress(ctx context.Context, domain *v1alpha1.Domain, l logr.Logger) error {
	ingress := &netwrkingv1.Ingress{}
	name := statsIngressName(domain)

	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: domain.Namespace}, ingress)
	if err == nil {
		return r.handleFoundIngress(ctx, ingress, domain, l)
	} else if !errors.IsNotFound(err) {
		return err
	}

	if !domain.Status.DNS.Stats.OK {
		return nil
	}

	ingress, err = r.buildDesiredIngress(domain)

	if err != nil {
		return err
	}

	return r.Create(ctx, ingress)
}

func (r *DomainReconciler) handleFoundIngress(ctx context.Context, ingress *netwrkingv1.Ingress, domain *v1alpha1.Domain, l logr.Logger) error {
	if domain.Status.DNS.Stats.OK {
		return r.reconcileExistingIngress(ctx, ingress, domain, l)
	}

	if ingress.DeletionTimestamp == nil {
		return r.Delete(ctx, ingress)
	}

	return nil
}

func (r *DomainReconciler) reconcileExistingIngress(ctx context.Context, ingress *netwrkingv1.Ingress, domain *v1alpha1.Domain, l logr.Logger) error {
	toUpdate := false
	for key, value := range domain.Spec.Ingress.Annotations {
		if v, ok := ingress.Annotations[key]; !ok || v != value {
			toUpdate = true
			ingress.Annotations[key] = value
		}
	}

	desiredSpec := buildIngressSpec(domain)
	if !reflect.DeepEqual(ingress.Spec, desiredSpec) {
		toUpdate = true
		ingress.Spec = desiredSpec
	}

	l.Info("updating ingress", "ingress", ingress, "to update", toUpdate)

	if !toUpdate {
		return nil
	}

	l.Info("updating ingress", "ingress", ingress.Spec)

	return r.Update(ctx, ingress)
}

func mapDNSCheckStats2DomainDNSResult(stats checker.DNSCheckStats) corev1alpha1.DNSStatusStats {
	return corev1alpha1.DNSStatusStats{
		OK:     stats.Result(),
		CntOK:  stats.CntOK,
		CntErr: stats.CntErr,
		CntKO:  stats.CntKO,
	}
}

func (r *DomainReconciler) checkDomainDNS(ctx context.Context, l logr.Logger, domain *corev1alpha1.Domain) (corev1alpha1.DNSStatus, error) {
	l.Info("checking domain dns", "domain", domain.Spec.BaseDomain)

	dkimStats := r.DNSChecker.CheckDomainDKim(ctx, domain)
	spfStats := r.DNSChecker.CheckDomainSPF(ctx, domain)
	domainStats := r.DNSChecker.CheckDomainStatsDNS(ctx, domain)

	return corev1alpha1.DNSStatus{
		Stats: mapDNSCheckStats2DomainDNSResult(domainStats),
		DKIM:  mapDNSCheckStats2DomainDNSResult(dkimStats),
		SFP:   mapDNSCheckStats2DomainDNSResult(spfStats),
	}, nil
}

func (r *DomainReconciler) buildDesiredIngress(domain *corev1alpha1.Domain) (*netwrkingv1.Ingress, error) {
	name := statsIngressName(domain)

	ing := &netwrkingv1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:        name,
			Namespace:   domain.Namespace,
			Annotations: domain.Spec.Ingress.Annotations,
		},
		Spec: buildIngressSpec(domain),
	}

	if err := ctrl.SetControllerReference(domain, ing, r.Scheme); err != nil {
		return ing, err
	}

	return ing, nil
}

func buildIngressSpec(domain *corev1alpha1.Domain) netwrkingv1.IngressSpec {
	pathPrefix := netwrkingv1.PathTypePrefix
	statsDomain := fmt.Sprintf("%s.%s", domain.Spec.StatsPrefix, domain.Spec.DomainName)

	tlsSecret := fmt.Sprintf("%s-tls", statsDomain)

	return netwrkingv1.IngressSpec{
		Rules: []netwrkingv1.IngressRule{
			{
				Host: statsDomain,
				IngressRuleValue: netwrkingv1.IngressRuleValue{
					HTTP: &netwrkingv1.HTTPIngressRuleValue{
						Paths: []netwrkingv1.HTTPIngressPath{
							{
								Path:     "/stats",
								PathType: &pathPrefix,
								Backend: netwrkingv1.IngressBackend{
									Service: ingressService(domain),
								},
							},
						},
					},
				},
			},
		},
		TLS: []netwrkingv1.IngressTLS{
			{
				Hosts:      []string{statsDomain},
				SecretName: tlsSecret,
			},
		},
	}
}

func ingressService(domain *corev1alpha1.Domain) *netwrkingv1.IngressServiceBackend {
	return &netwrkingv1.IngressServiceBackend{
		Name: domain.Spec.Ingress.Service.Name,
		Port: netwrkingv1.ServiceBackendPort{
			Number: domain.Spec.Ingress.Service.Port,
		},
	}
}

func statsIngressName(domain *corev1alpha1.Domain) string {
	return fmt.Sprintf("%s-stats", domain.Name)
}

func dnsReady(dnsStatus corev1alpha1.DNSStatus) bool {
	return dnsStatus.DKIM.OK && dnsStatus.Stats.OK && dnsStatus.SFP.OK
}

func computeReconcileInterval(domain *corev1alpha1.Domain) time.Duration {
	if dnsReady(domain.Status.DNS) {
		return 1 * time.Hour
	}

	return 1 * time.Minute
}
