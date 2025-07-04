// Copyright The prometheus-operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	corev1 "k8s.io/api/core/v1"
)

// ProberSpecApplyConfiguration represents a declarative configuration of the ProberSpec type for use
// with apply.
type ProberSpecApplyConfiguration struct {
	URL                           *string `json:"url,omitempty"`
	Scheme                        *string `json:"scheme,omitempty"`
	Path                          *string `json:"path,omitempty"`
	ProxyConfigApplyConfiguration `json:",inline"`
}

// ProberSpecApplyConfiguration constructs a declarative configuration of the ProberSpec type for use with
// apply.
func ProberSpec() *ProberSpecApplyConfiguration {
	return &ProberSpecApplyConfiguration{}
}

// WithURL sets the URL field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the URL field is set to the value of the last call.
func (b *ProberSpecApplyConfiguration) WithURL(value string) *ProberSpecApplyConfiguration {
	b.URL = &value
	return b
}

// WithScheme sets the Scheme field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Scheme field is set to the value of the last call.
func (b *ProberSpecApplyConfiguration) WithScheme(value string) *ProberSpecApplyConfiguration {
	b.Scheme = &value
	return b
}

// WithPath sets the Path field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Path field is set to the value of the last call.
func (b *ProberSpecApplyConfiguration) WithPath(value string) *ProberSpecApplyConfiguration {
	b.Path = &value
	return b
}

// WithProxyURL sets the ProxyURL field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ProxyURL field is set to the value of the last call.
func (b *ProberSpecApplyConfiguration) WithProxyURL(value string) *ProberSpecApplyConfiguration {
	b.ProxyConfigApplyConfiguration.ProxyURL = &value
	return b
}

// WithNoProxy sets the NoProxy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NoProxy field is set to the value of the last call.
func (b *ProberSpecApplyConfiguration) WithNoProxy(value string) *ProberSpecApplyConfiguration {
	b.ProxyConfigApplyConfiguration.NoProxy = &value
	return b
}

// WithProxyFromEnvironment sets the ProxyFromEnvironment field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ProxyFromEnvironment field is set to the value of the last call.
func (b *ProberSpecApplyConfiguration) WithProxyFromEnvironment(value bool) *ProberSpecApplyConfiguration {
	b.ProxyConfigApplyConfiguration.ProxyFromEnvironment = &value
	return b
}

// WithProxyConnectHeader puts the entries into the ProxyConnectHeader field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the ProxyConnectHeader field,
// overwriting an existing map entries in ProxyConnectHeader field with the same key.
func (b *ProberSpecApplyConfiguration) WithProxyConnectHeader(entries map[string][]corev1.SecretKeySelector) *ProberSpecApplyConfiguration {
	if b.ProxyConfigApplyConfiguration.ProxyConnectHeader == nil && len(entries) > 0 {
		b.ProxyConfigApplyConfiguration.ProxyConnectHeader = make(map[string][]corev1.SecretKeySelector, len(entries))
	}
	for k, v := range entries {
		b.ProxyConfigApplyConfiguration.ProxyConnectHeader[k] = v
	}
	return b
}
