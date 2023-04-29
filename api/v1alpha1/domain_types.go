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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// DomainSpec defines the desired state of Domain
type DomainSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Foo is an example field of Domain. Edit domain_types.go to remove/update

	//+kubebuilder:validation:Required
	DomainName string `json:"domainName,omitempty"`

	//+kubebuilder:validation:Required
	BaseDomain string `json:"baseDomain,omitempty"`

	//+kubebuilder:validation:Required
	StatsPrefix string `json:"statsPrefix,omitempty"`

	//+kubebuilder:validation:Required
	DKim DKim `json:"dkim,omitempty"`

	Ingress DomainIngressSpec `json:"ingress,omitempty"`
}

type DomainIngressSpec struct {
	ClassName string `json:"className"`

	//+kubebuilder:validation:Required
	Service DomainIngressServiceSpec `json:"service"`

	Annotations map[string]string `json:"annotations"`
}

type DomainIngressServiceSpec struct {
	//+kubebuilder:validation:Required
	Name string `json:"name"`

	//+kubebuilder:validation:Required
	Port int32 `json:"port"`
}

type DKim struct {
	//+kubebuilder:validation:Required
	Selector string `json:"selector,omitempty"`

	//+kubebuilder:validation:Required
	PublicKey string `json:"publicKey,omitempty"`
}

// DomainStatus defines the observed state of Domain
type DomainStatus struct {
	DNS DNSStatus `json:"dns"`
}

type DNSStatus struct {
	Stats DNSStatusStats `json:"stats"`
	DKIM  DNSStatusStats `json:"dkim"`
	SFP   DNSStatusStats `json:"spf"`
}

type DNSStatusStats struct {
	OK     bool `json:"ok"`
	CntOK  int  `json:"cnt_ok"`
	CntErr int  `json:"cnt_err"`
	CntKO  int  `json:"cnt_ko"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Domain is the Schema for the domains API
// +kubebuilder:printcolumn:name="Domain",type=string,JSONPath=`.spec.domainName`
// +kubebuilder:printcolumn:name="DNS Check DKIM",type=boolean,JSONPath=`.status.dns.dkim.ok`
// +kubebuilder:printcolumn:name="DNS Check SPF",type=boolean,JSONPath=`.status.dns.spf.ok`
// +kubebuilder:printcolumn:name="DNS Check Stats",type=boolean,JSONPath=`.status.dns.stats.ok`
type Domain struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DomainSpec   `json:"spec,omitempty"`
	Status DomainStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// DomainList contains a list of Domain
type DomainList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Domain `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Domain{}, &DomainList{})
}
