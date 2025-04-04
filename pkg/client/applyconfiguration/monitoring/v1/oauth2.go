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

// OAuth2ApplyConfiguration represents a declarative configuration of the OAuth2 type for use
// with apply.
type OAuth2ApplyConfiguration struct {
	ClientID                      *SecretOrConfigMapApplyConfiguration `json:"clientId,omitempty"`
	ClientSecret                  *corev1.SecretKeySelector            `json:"clientSecret,omitempty"`
	TokenURL                      *string                              `json:"tokenUrl,omitempty"`
	Scopes                        []string                             `json:"scopes,omitempty"`
	EndpointParams                map[string]string                    `json:"endpointParams,omitempty"`
	TLSConfig                     *SafeTLSConfigApplyConfiguration     `json:"tlsConfig,omitempty"`
	ProxyConfigApplyConfiguration `json:",inline"`
}

// OAuth2ApplyConfiguration constructs a declarative configuration of the OAuth2 type for use with
// apply.
func OAuth2() *OAuth2ApplyConfiguration {
	return &OAuth2ApplyConfiguration{}
}

// WithClientID sets the ClientID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClientID field is set to the value of the last call.
func (b *OAuth2ApplyConfiguration) WithClientID(value *SecretOrConfigMapApplyConfiguration) *OAuth2ApplyConfiguration {
	b.ClientID = value
	return b
}

// WithClientSecret sets the ClientSecret field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClientSecret field is set to the value of the last call.
func (b *OAuth2ApplyConfiguration) WithClientSecret(value corev1.SecretKeySelector) *OAuth2ApplyConfiguration {
	b.ClientSecret = &value
	return b
}

// WithTokenURL sets the TokenURL field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TokenURL field is set to the value of the last call.
func (b *OAuth2ApplyConfiguration) WithTokenURL(value string) *OAuth2ApplyConfiguration {
	b.TokenURL = &value
	return b
}

// WithScopes adds the given value to the Scopes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Scopes field.
func (b *OAuth2ApplyConfiguration) WithScopes(values ...string) *OAuth2ApplyConfiguration {
	for i := range values {
		b.Scopes = append(b.Scopes, values[i])
	}
	return b
}

// WithEndpointParams puts the entries into the EndpointParams field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the EndpointParams field,
// overwriting an existing map entries in EndpointParams field with the same key.
func (b *OAuth2ApplyConfiguration) WithEndpointParams(entries map[string]string) *OAuth2ApplyConfiguration {
	if b.EndpointParams == nil && len(entries) > 0 {
		b.EndpointParams = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.EndpointParams[k] = v
	}
	return b
}

// WithTLSConfig sets the TLSConfig field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the TLSConfig field is set to the value of the last call.
func (b *OAuth2ApplyConfiguration) WithTLSConfig(value *SafeTLSConfigApplyConfiguration) *OAuth2ApplyConfiguration {
	b.TLSConfig = value
	return b
}

// WithProxyURL sets the ProxyURL field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ProxyURL field is set to the value of the last call.
func (b *OAuth2ApplyConfiguration) WithProxyURL(value string) *OAuth2ApplyConfiguration {
	b.ProxyConfigApplyConfiguration.ProxyURL = &value
	return b
}

// WithNoProxy sets the NoProxy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the NoProxy field is set to the value of the last call.
func (b *OAuth2ApplyConfiguration) WithNoProxy(value string) *OAuth2ApplyConfiguration {
	b.ProxyConfigApplyConfiguration.NoProxy = &value
	return b
}

// WithProxyFromEnvironment sets the ProxyFromEnvironment field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ProxyFromEnvironment field is set to the value of the last call.
func (b *OAuth2ApplyConfiguration) WithProxyFromEnvironment(value bool) *OAuth2ApplyConfiguration {
	b.ProxyConfigApplyConfiguration.ProxyFromEnvironment = &value
	return b
}

// WithProxyConnectHeader puts the entries into the ProxyConnectHeader field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the ProxyConnectHeader field,
// overwriting an existing map entries in ProxyConnectHeader field with the same key.
func (b *OAuth2ApplyConfiguration) WithProxyConnectHeader(entries map[string][]corev1.SecretKeySelector) *OAuth2ApplyConfiguration {
	if b.ProxyConfigApplyConfiguration.ProxyConnectHeader == nil && len(entries) > 0 {
		b.ProxyConfigApplyConfiguration.ProxyConnectHeader = make(map[string][]corev1.SecretKeySelector, len(entries))
	}
	for k, v := range entries {
		b.ProxyConfigApplyConfiguration.ProxyConnectHeader[k] = v
	}
	return b
}
