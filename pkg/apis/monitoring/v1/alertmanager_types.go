// Copyright 2018 The prometheus-operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	AlertmanagersKind   = "Alertmanager"
	AlertmanagerName    = "alertmanagers"
	AlertManagerKindKey = "alertmanager"
)

// +genclient
// +k8s:openapi-gen=true
// +kubebuilder:resource:categories="prometheus-operator",shortName="am"
// +kubebuilder:printcolumn:name="Version",type="string",JSONPath=".spec.version",description="The version of Alertmanager"
// +kubebuilder:printcolumn:name="Replicas",type="integer",JSONPath=".spec.replicas",description="The number of desired replicas"
// +kubebuilder:printcolumn:name="Ready",type="integer",JSONPath=".status.availableReplicas",description="The number of ready replicas"
// +kubebuilder:printcolumn:name="Reconciled",type="string",JSONPath=".status.conditions[?(@.type == 'Reconciled')].status"
// +kubebuilder:printcolumn:name="Available",type="string",JSONPath=".status.conditions[?(@.type == 'Available')].status"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:printcolumn:name="Paused",type="boolean",JSONPath=".status.paused",description="Whether the resource reconciliation is paused or not",priority=1
// +kubebuilder:subresource:status
// +kubebuilder:subresource:scale:specpath=.spec.replicas,statuspath=.status.replicas,selectorpath=.status.selector
// +genclient:method=GetScale,verb=get,subresource=scale,result=k8s.io/api/autoscaling/v1.Scale
// +genclient:method=UpdateScale,verb=update,subresource=scale,input=k8s.io/api/autoscaling/v1.Scale,result=k8s.io/api/autoscaling/v1.Scale

// The `Alertmanager` custom resource definition (CRD) defines a desired [Alertmanager](https://prometheus.io/docs/alerting) setup to run in a Kubernetes cluster. It allows to specify many options such as the number of replicas, persistent storage and many more.
//
// For each `Alertmanager` resource, the Operator deploys a `StatefulSet` in the same namespace. When there are two or more configured replicas, the Operator runs the Alertmanager instances in high-availability mode.
//
// The resource defines via label and namespace selectors which `AlertmanagerConfig` objects should be associated to the deployed Alertmanager instances.
type Alertmanager struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// Specification of the desired behavior of the Alertmanager cluster. More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Spec AlertmanagerSpec `json:"spec"`
	// Most recent observed status of the Alertmanager cluster. Read-only.
	// More info:
	// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	Status AlertmanagerStatus `json:"status,omitempty"`
}

// DeepCopyObject implements the runtime.Object interface.
func (l *Alertmanager) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// AlertmanagerSpec is a specification of the desired behavior of the Alertmanager cluster. More info:
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
// +k8s:openapi-gen=true
type AlertmanagerSpec struct {
	// PodMetadata configures labels and annotations which are propagated to the Alertmanager pods.
	//
	// The following items are reserved and cannot be overridden:
	// * "alertmanager" label, set to the name of the Alertmanager instance.
	// * "app.kubernetes.io/instance" label, set to the name of the Alertmanager instance.
	// * "app.kubernetes.io/managed-by" label, set to "prometheus-operator".
	// * "app.kubernetes.io/name" label, set to "alertmanager".
	// * "app.kubernetes.io/version" label, set to the Alertmanager version.
	// * "kubectl.kubernetes.io/default-container" annotation, set to "alertmanager".
	PodMetadata *EmbeddedObjectMetadata `json:"podMetadata,omitempty"`
	// Image if specified has precedence over baseImage, tag and sha
	// combinations. Specifying the version is still necessary to ensure the
	// Prometheus Operator knows what version of Alertmanager is being
	// configured.
	Image *string `json:"image,omitempty"`
	// Image pull policy for the 'alertmanager', 'init-config-reloader' and 'config-reloader' containers.
	// See https://kubernetes.io/docs/concepts/containers/images/#image-pull-policy for more details.
	// +kubebuilder:validation:Enum="";Always;Never;IfNotPresent
	ImagePullPolicy v1.PullPolicy `json:"imagePullPolicy,omitempty"`
	// Version the cluster should be on.
	Version string `json:"version,omitempty"`
	// Tag of Alertmanager container image to be deployed. Defaults to the value of `version`.
	// Version is ignored if Tag is set.
	// Deprecated: use 'image' instead. The image tag can be specified as part of the image URL.
	Tag string `json:"tag,omitempty"`
	// SHA of Alertmanager container image to be deployed. Defaults to the value of `version`.
	// Similar to a tag, but the SHA explicitly deploys an immutable container image.
	// Version and Tag are ignored if SHA is set.
	// Deprecated: use 'image' instead. The image digest can be specified as part of the image URL.
	SHA string `json:"sha,omitempty"`
	// Base image that is used to deploy pods, without tag.
	// Deprecated: use 'image' instead.
	BaseImage string `json:"baseImage,omitempty"`
	// An optional list of references to secrets in the same namespace
	// to use for pulling prometheus and alertmanager images from registries
	// see https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/
	ImagePullSecrets []v1.LocalObjectReference `json:"imagePullSecrets,omitempty"`
	// Secrets is a list of Secrets in the same namespace as the Alertmanager
	// object, which shall be mounted into the Alertmanager Pods.
	// Each Secret is added to the StatefulSet definition as a volume named `secret-<secret-name>`.
	// The Secrets are mounted into `/etc/alertmanager/secrets/<secret-name>` in the 'alertmanager' container.
	Secrets []string `json:"secrets,omitempty"`
	// ConfigMaps is a list of ConfigMaps in the same namespace as the Alertmanager
	// object, which shall be mounted into the Alertmanager Pods.
	// Each ConfigMap is added to the StatefulSet definition as a volume named `configmap-<configmap-name>`.
	// The ConfigMaps are mounted into `/etc/alertmanager/configmaps/<configmap-name>` in the 'alertmanager' container.
	ConfigMaps []string `json:"configMaps,omitempty"`
	// ConfigSecret is the name of a Kubernetes Secret in the same namespace as the
	// Alertmanager object, which contains the configuration for this Alertmanager
	// instance. If empty, it defaults to `alertmanager-<alertmanager-name>`.
	//
	// The Alertmanager configuration should be available under the
	// `alertmanager.yaml` key. Additional keys from the original secret are
	// copied to the generated secret and mounted into the
	// `/etc/alertmanager/config` directory in the `alertmanager` container.
	//
	// If either the secret or the `alertmanager.yaml` key is missing, the
	// operator provisions a minimal Alertmanager configuration with one empty
	// receiver (effectively dropping alert notifications).
	ConfigSecret string `json:"configSecret,omitempty"`
	// Log level for Alertmanager to be configured with.
	// +kubebuilder:validation:Enum="";debug;info;warn;error
	LogLevel string `json:"logLevel,omitempty"`
	// Log format for Alertmanager to be configured with.
	// +kubebuilder:validation:Enum="";logfmt;json
	LogFormat string `json:"logFormat,omitempty"`
	// Size is the expected size of the alertmanager cluster. The controller will
	// eventually make the size of the running cluster equal to the expected
	// size.
	Replicas *int32 `json:"replicas,omitempty"`
	// Time duration Alertmanager shall retain data for. Default is '120h',
	// and must match the regular expression `[0-9]+(ms|s|m|h)` (milliseconds seconds minutes hours).
	// +kubebuilder:default:="120h"
	Retention GoDuration `json:"retention,omitempty"`
	// Storage is the definition of how storage will be used by the Alertmanager
	// instances.
	Storage *StorageSpec `json:"storage,omitempty"`
	// Volumes allows configuration of additional volumes on the output StatefulSet definition.
	// Volumes specified will be appended to other volumes that are generated as a result of
	// StorageSpec objects.
	Volumes []v1.Volume `json:"volumes,omitempty"`
	// VolumeMounts allows configuration of additional VolumeMounts on the output StatefulSet definition.
	// VolumeMounts specified will be appended to other VolumeMounts in the alertmanager container,
	// that are generated as a result of StorageSpec objects.
	VolumeMounts []v1.VolumeMount `json:"volumeMounts,omitempty"`
	// The field controls if and how PVCs are deleted during the lifecycle of a StatefulSet.
	// The default behavior is all PVCs are retained.
	// This is an alpha field from kubernetes 1.23 until 1.26 and a beta field from 1.26.
	// It requires enabling the StatefulSetAutoDeletePVC feature gate.
	//
	// +optional
	PersistentVolumeClaimRetentionPolicy *appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy `json:"persistentVolumeClaimRetentionPolicy,omitempty"`
	// The external URL the Alertmanager instances will be available under. This is
	// necessary to generate correct URLs. This is necessary if Alertmanager is not
	// served from root of a DNS name.
	ExternalURL string `json:"externalUrl,omitempty"`
	// The route prefix Alertmanager registers HTTP handlers for. This is useful,
	// if using ExternalURL and a proxy is rewriting HTTP routes of a request,
	// and the actual ExternalURL is still true, but the server serves requests
	// under a different route prefix. For example for use with `kubectl proxy`.
	RoutePrefix string `json:"routePrefix,omitempty"`
	// If set to true all actions on the underlying managed objects are not
	// going to be performed, except for delete actions.
	Paused bool `json:"paused,omitempty"`
	// Define which Nodes the Pods are scheduled on.
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`
	// Define resources requests and limits for single Pods.
	Resources v1.ResourceRequirements `json:"resources,omitempty"`
	// If specified, the pod's scheduling constraints.
	Affinity *v1.Affinity `json:"affinity,omitempty"`
	// If specified, the pod's tolerations.
	Tolerations []v1.Toleration `json:"tolerations,omitempty"`
	// If specified, the pod's topology spread constraints.
	TopologySpreadConstraints []v1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
	// SecurityContext holds pod-level security attributes and common container settings.
	// This defaults to the default PodSecurityContext.
	SecurityContext *v1.PodSecurityContext `json:"securityContext,omitempty"`
	// Defines the DNS policy for the pods.
	//
	// +optional
	DNSPolicy *DNSPolicy `json:"dnsPolicy,omitempty"`
	// Defines the DNS configuration for the pods.
	//
	// +optional
	DNSConfig *PodDNSConfig `json:"dnsConfig,omitempty"`
	// Indicates whether information about services should be injected into pod's environment variables
	// +optional
	EnableServiceLinks *bool `json:"enableServiceLinks,omitempty"`
	// The name of the service name used by the underlying StatefulSet(s) as the governing service.
	// If defined, the Service  must be created before the Alertmanager resource in the same namespace and it must define a selector that matches the pod labels.
	// If empty, the operator will create and manage a headless service named `alertmanager-operated` for Alermanager resources.
	// When deploying multiple Alertmanager resources in the same namespace, it is recommended to specify a different value for each.
	// See https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#stable-network-id for more details.
	// +optional
	// +kubebuilder:validation:MinLength=1
	ServiceName *string `json:"serviceName,omitempty"`
	// ServiceAccountName is the name of the ServiceAccount to use to run the
	// Prometheus Pods.
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// ListenLocal makes the Alertmanager server listen on loopback, so that it
	// does not bind against the Pod IP. Note this is only for the Alertmanager
	// UI, not the gossip communication.
	ListenLocal bool `json:"listenLocal,omitempty"`
	// Containers allows injecting additional containers. This is meant to
	// allow adding an authentication proxy to an Alertmanager pod.
	// Containers described here modify an operator generated container if they
	// share the same name and modifications are done via a strategic merge
	// patch. The current container names are: `alertmanager` and
	// `config-reloader`. Overriding containers is entirely outside the scope
	// of what the maintainers will support and by doing so, you accept that
	// this behaviour may break at any time without notice.
	Containers []v1.Container `json:"containers,omitempty"`
	// InitContainers allows adding initContainers to the pod definition. Those can be used to e.g.
	// fetch secrets for injection into the Alertmanager configuration from external sources. Any
	// errors during the execution of an initContainer will lead to a restart of the Pod. More info: https://kubernetes.io/docs/concepts/workloads/pods/init-containers/
	// InitContainers described here modify an operator
	// generated init containers if they share the same name and modifications are
	// done via a strategic merge patch. The current init container name is:
	// `init-config-reloader`. Overriding init containers is entirely outside the
	// scope of what the maintainers will support and by doing so, you accept that
	// this behaviour may break at any time without notice.
	InitContainers []v1.Container `json:"initContainers,omitempty"`
	// Priority class assigned to the Pods
	PriorityClassName string `json:"priorityClassName,omitempty"`
	// AdditionalPeers allows injecting a set of additional Alertmanagers to peer with to form a highly available cluster.
	AdditionalPeers []string `json:"additionalPeers,omitempty"`
	// ClusterAdvertiseAddress is the explicit address to advertise in cluster.
	// Needs to be provided for non RFC1918 [1] (public) addresses.
	// [1] RFC1918: https://tools.ietf.org/html/rfc1918
	ClusterAdvertiseAddress string `json:"clusterAdvertiseAddress,omitempty"`
	// Interval between gossip attempts.
	ClusterGossipInterval GoDuration `json:"clusterGossipInterval,omitempty"`
	// Defines the identifier that uniquely identifies the Alertmanager cluster.
	// You should only set it when the Alertmanager cluster includes Alertmanager instances which are external to this Alertmanager resource. In practice, the addresses of the external instances are provided via the `.spec.additionalPeers` field.
	ClusterLabel *string `json:"clusterLabel,omitempty"`
	// Interval between pushpull attempts.
	ClusterPushpullInterval GoDuration `json:"clusterPushpullInterval,omitempty"`
	// Timeout for cluster peering.
	ClusterPeerTimeout GoDuration `json:"clusterPeerTimeout,omitempty"`
	// Port name used for the pods and governing service.
	// Defaults to `web`.
	// +kubebuilder:default:="web"
	PortName string `json:"portName,omitempty"`
	// ForceEnableClusterMode ensures Alertmanager does not deactivate the cluster mode when running with a single replica.
	// Use case is e.g. spanning an Alertmanager cluster across Kubernetes clusters with a single replica in each.
	ForceEnableClusterMode bool `json:"forceEnableClusterMode,omitempty"`
	// AlertmanagerConfigs to be selected for to merge and configure Alertmanager with.
	AlertmanagerConfigSelector *metav1.LabelSelector `json:"alertmanagerConfigSelector,omitempty"`
	// Namespaces to be selected for AlertmanagerConfig discovery. If nil, only
	// check own namespace.
	AlertmanagerConfigNamespaceSelector *metav1.LabelSelector `json:"alertmanagerConfigNamespaceSelector,omitempty"`

	// AlertmanagerConfigMatcherStrategy defines how AlertmanagerConfig objects
	// process incoming alerts.
	AlertmanagerConfigMatcherStrategy AlertmanagerConfigMatcherStrategy `json:"alertmanagerConfigMatcherStrategy,omitempty"`

	// Minimum number of seconds for which a newly created pod should be ready
	// without any of its container crashing for it to be considered available.
	// Defaults to 0 (pod will be considered available as soon as it is ready)
	// This is an alpha field from kubernetes 1.22 until 1.24 which requires enabling the StatefulSetMinReadySeconds feature gate.
	// +optional
	MinReadySeconds *uint32 `json:"minReadySeconds,omitempty"`
	// Pods' hostAliases configuration
	// +listType=map
	// +listMapKey=ip
	HostAliases []HostAlias `json:"hostAliases,omitempty"`
	// Defines the web command line flags when starting Alertmanager.
	Web *AlertmanagerWebSpec `json:"web,omitempty"`
	// Defines the limits command line flags when starting Alertmanager.
	Limits *AlertmanagerLimitsSpec `json:"limits,omitempty"`
	// Configures the mutual TLS configuration for the Alertmanager cluster's gossip protocol.
	//
	// It requires Alertmanager >= 0.24.0.
	//+optional
	ClusterTLS *ClusterTLSConfig `json:"clusterTLS,omitempty"`
	// alertmanagerConfiguration specifies the configuration of Alertmanager.
	//
	// If defined, it takes precedence over the `configSecret` field.
	//
	// This is an *experimental feature*, it may change in any upcoming release
	// in a breaking way.
	//
	//+optional
	AlertmanagerConfiguration *AlertmanagerConfiguration `json:"alertmanagerConfiguration,omitempty"`
	// AutomountServiceAccountToken indicates whether a service account token should be automatically mounted in the pod.
	// If the service account has `automountServiceAccountToken: true`, set the field to `false` to opt out of automounting API credentials.
	// +optional
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken,omitempty"`
	// Enable access to Alertmanager feature flags. By default, no features are enabled.
	// Enabling features which are disabled by default is entirely outside the
	// scope of what the maintainers will support and by doing so, you accept
	// that this behaviour may break at any time without notice.
	//
	// It requires Alertmanager >= 0.27.0.
	// +optional
	EnableFeatures []string `json:"enableFeatures,omitempty"`
	// AdditionalArgs allows setting additional arguments for the 'Alertmanager' container.
	// It is intended for e.g. activating hidden flags which are not supported by
	// the dedicated configuration options yet. The arguments are passed as-is to the
	// Alertmanager container which may cause issues if they are invalid or not supported
	// by the given Alertmanager version.
	// +optional
	AdditionalArgs []Argument `json:"additionalArgs,omitempty"`

	// Optional duration in seconds the pod needs to terminate gracefully.
	// Value must be non-negative integer. The value zero indicates stop immediately via
	// the kill signal (no opportunity to shut down) which may lead to data corruption.
	//
	// Defaults to 120 seconds.
	//
	// +kubebuilder:validation:Minimum:=0
	// +optional
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`
}

type AlertmanagerConfigMatcherStrategy struct {
	// AlertmanagerConfigMatcherStrategyType defines the strategy used by
	// AlertmanagerConfig objects to match alerts in the routes and inhibition
	// rules.
	//
	// The default value is `OnNamespace`.
	//
	// +kubebuilder:validation:Enum="OnNamespace";"OnNamespaceExceptForAlertmanagerNamespace";"None"
	// +kubebuilder:default:="OnNamespace"
	Type AlertmanagerConfigMatcherStrategyType `json:"type,omitempty"`
}

type AlertmanagerConfigMatcherStrategyType string

const (
	// With `OnNamespace`, the route and inhibition rules of an
	// AlertmanagerConfig object only process alerts that have a `namespace`
	// label equal to the namespace of the object.
	OnNamespaceConfigMatcherStrategyType AlertmanagerConfigMatcherStrategyType = "OnNamespace"

	// With `OnNamespaceExceptForAlertmanagerNamespace`, the route and inhibition rules of an
	// AlertmanagerConfig object only process alerts that have a `namespace`
	// label equal to the namespace of the object, unless the AlertmanagerConfig object
	// is in the same namespace as the Alertmanager object, where it will process all alerts.
	OnNamespaceExceptForAlertmanagerNamespaceConfigMatcherStrategyType AlertmanagerConfigMatcherStrategyType = "OnNamespaceExceptForAlertmanagerNamespace"

	// With `None`, the route and inhbition rules of an AlertmanagerConfig
	// object process all incoming alerts.
	NoneConfigMatcherStrategyType AlertmanagerConfigMatcherStrategyType = "None"
)

// AlertmanagerConfiguration defines the Alertmanager configuration.
// +k8s:openapi-gen=true
type AlertmanagerConfiguration struct {
	// The name of the AlertmanagerConfig resource which is used to generate the Alertmanager configuration.
	// It must be defined in the same namespace as the Alertmanager object.
	// The operator will not enforce a `namespace` label for routes and inhibition rules.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name,omitempty"`
	// Defines the global parameters of the Alertmanager configuration.
	// +optional
	Global *AlertmanagerGlobalConfig `json:"global,omitempty"`
	// Custom notification templates.
	// +optional
	Templates []SecretOrConfigMap `json:"templates,omitempty"`
}

// AlertmanagerGlobalConfig configures parameters that are valid in all other configuration contexts.
// See https://prometheus.io/docs/alerting/latest/configuration/#configuration-file
type AlertmanagerGlobalConfig struct {
	// Configures global SMTP parameters.
	// +optional
	SMTPConfig *GlobalSMTPConfig `json:"smtp,omitempty"`

	// ResolveTimeout is the default value used by alertmanager if the alert does
	// not include EndsAt, after this time passes it can declare the alert as resolved if it has not been updated.
	// This has no impact on alerts from Prometheus, as they always include EndsAt.
	ResolveTimeout Duration `json:"resolveTimeout,omitempty"`

	// HTTP client configuration.
	HTTPConfig *HTTPConfig `json:"httpConfig,omitempty"`

	// The default Slack API URL.
	SlackAPIURL *v1.SecretKeySelector `json:"slackApiUrl,omitempty"`

	// The default OpsGenie API URL.
	OpsGenieAPIURL *v1.SecretKeySelector `json:"opsGenieApiUrl,omitempty"`

	// The default OpsGenie API Key.
	OpsGenieAPIKey *v1.SecretKeySelector `json:"opsGenieApiKey,omitempty"`

	// The default Pagerduty URL.
	PagerdutyURL *string `json:"pagerdutyUrl,omitempty"`

	// The default Telegram config
	TelegramConfig *GlobalTelegramConfig `json:"telegram,omitempty"`

	// The default configuration for Jira.
	JiraConfig *GlobalJiraConfig `json:"jira,omitempty"`

	// The default configuration for VictorOps.
	VictorOpsConfig *GlobalVictorOpsConfig `json:"victorops,omitempty"`

	// The default configuration for Rocket Chat.
	RocketChatConfig *GlobalRocketChatConfig `json:"rocketChat,omitempty"`

	// The default configuration for Jira.
	WebexConfig *GlobalWebexConfig `json:"webex,omitempty"`

	// The default WeChat Config
	// +optional
	WeChatConfig *GlobalWeChatConfig `json:"wechat,omitempty"`
}

// AlertmanagerStatus is the most recent observed status of the Alertmanager cluster. Read-only.
// More info:
// https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
// +k8s:openapi-gen=true
type AlertmanagerStatus struct {
	// Represents whether any actions on the underlying managed objects are
	// being performed. Only delete actions will be performed.
	Paused bool `json:"paused"`
	// Total number of non-terminated pods targeted by this Alertmanager
	// object (their labels match the selector).
	Replicas int32 `json:"replicas"`
	// Total number of non-terminated pods targeted by this Alertmanager
	// object that have the desired version spec.
	UpdatedReplicas int32 `json:"updatedReplicas"`
	// Total number of available pods (ready for at least minReadySeconds)
	// targeted by this Alertmanager cluster.
	AvailableReplicas int32 `json:"availableReplicas"`
	// Total number of unavailable pods targeted by this Alertmanager object.
	UnavailableReplicas int32 `json:"unavailableReplicas"`
	// The selector used to match the pods targeted by this Alertmanager object.
	Selector string `json:"selector,omitempty"`
	// The current state of the Alertmanager object.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []Condition `json:"conditions,omitempty"`
}

func (a *Alertmanager) ExpectedReplicas() int {
	if a.Spec.Replicas == nil {
		return 1
	}
	return int(*a.Spec.Replicas)
}

func (a *Alertmanager) SetReplicas(i int)            { a.Status.Replicas = int32(i) }
func (a *Alertmanager) SetUpdatedReplicas(i int)     { a.Status.UpdatedReplicas = int32(i) }
func (a *Alertmanager) SetAvailableReplicas(i int)   { a.Status.AvailableReplicas = int32(i) }
func (a *Alertmanager) SetUnavailableReplicas(i int) { a.Status.UnavailableReplicas = int32(i) }

// AlertmanagerWebSpec defines the web command line flags when starting Alertmanager.
// +k8s:openapi-gen=true
type AlertmanagerWebSpec struct {
	WebConfigFileFields `json:",inline"`
	// Maximum number of GET requests processed concurrently. This corresponds to the
	// Alertmanager's `--web.get-concurrency` flag.
	// +optional
	GetConcurrency *uint32 `json:"getConcurrency,omitempty"`
	// Timeout for HTTP requests. This corresponds to the Alertmanager's
	// `--web.timeout` flag.
	// +optional
	Timeout *uint32 `json:"timeout,omitempty"`
}

// AlertmanagerLimitsSpec defines the limits command line flags when starting Alertmanager.
// +k8s:openapi-gen=true
type AlertmanagerLimitsSpec struct {
	// The maximum number active and pending silences. This corresponds to the
	// Alertmanager's `--silences.max-silences` flag.
	// It requires Alertmanager >= v0.28.0.
	//
	// +kubebuilder:validation:Minimum:=0
	// +optional
	MaxSilences *int32 `json:"maxSilences,omitempty"`
	// The maximum size of an individual silence as stored on disk. This corresponds to the Alertmanager's
	// `--silences.max-per-silence-bytes` flag.
	// It requires Alertmanager >= v0.28.0.
	//
	// +optional
	MaxPerSilenceBytes *ByteSize `json:"maxPerSilenceBytes,omitempty"`
}

// GlobalSMTPConfig configures global SMTP parameters.
// See https://prometheus.io/docs/alerting/latest/configuration/#configuration-file
type GlobalSMTPConfig struct {
	// The default SMTP From header field.
	// +optional
	From *string `json:"from,omitempty"`

	// The default SMTP smarthost used for sending emails.
	// +optional
	SmartHost *HostPort `json:"smartHost,omitempty"`

	// The default hostname to identify to the SMTP server.
	// +optional
	Hello *string `json:"hello,omitempty"`

	// SMTP Auth using CRAM-MD5, LOGIN and PLAIN. If empty, Alertmanager doesn't authenticate to the SMTP server.
	// +optional
	AuthUsername *string `json:"authUsername,omitempty"`

	// SMTP Auth using LOGIN and PLAIN.
	// +optional
	AuthPassword *v1.SecretKeySelector `json:"authPassword,omitempty"`

	// SMTP Auth using PLAIN
	// +optional
	AuthIdentity *string `json:"authIdentity,omitempty"`

	// SMTP Auth using CRAM-MD5.
	// +optional
	AuthSecret *v1.SecretKeySelector `json:"authSecret,omitempty"`

	// The default SMTP TLS requirement.
	// Note that Go does not support unencrypted connections to remote SMTP endpoints.
	// +optional
	RequireTLS *bool `json:"requireTLS,omitempty"`

	// The default TLS configuration for SMTP receivers
	// +optional
	TLSConfig *SafeTLSConfig `json:"tlsConfig,omitempty"`
}

// GlobalTelegramConfig configures global Telegram parameters.
type GlobalTelegramConfig struct {
	// The default Telegram API URL.
	//
	// It requires Alertmanager >= v0.24.0.
	// +optional
	APIURL *URL `json:"apiURL,omitempty"`
}

// GlobalJiraConfig configures global Jira parameters.
type GlobalJiraConfig struct {
	// The default Jira API URL.
	//
	// It requires Alertmanager >= v0.28.0.
	//
	// +optional
	APIURL *URL `json:"apiURL,omitempty"`
}

// GlobalRocketChatConfig configures global Rocket Chat parameters.
type GlobalRocketChatConfig struct {
	// The default Rocket Chat API URL.
	//
	// It requires Alertmanager >= v0.28.0.
	//
	// +optional
	APIURL *URL `json:"apiURL,omitempty"`

	// The default Rocket Chat token.
	//
	// It requires Alertmanager >= v0.28.0.
	//
	// +optional
	Token *v1.SecretKeySelector `json:"token,omitempty"`

	// The default Rocket Chat Token ID.
	//
	// It requires Alertmanager >= v0.28.0.
	//
	// +optional
	TokenID *v1.SecretKeySelector `json:"tokenID,omitempty"`
}

// GlobalWebexConfig configures global Webex parameters.
// See https://prometheus.io/docs/alerting/latest/configuration/#configuration-file
type GlobalWebexConfig struct {
	// The default Webex API URL.
	//
	// It requires Alertmanager >= v0.25.0.
	//
	// +optional
	APIURL *URL `json:"apiURL,omitempty"`
}

type GlobalWeChatConfig struct {
	// The default WeChat API URL.
	// The default value is "https://qyapi.weixin.qq.com/cgi-bin/"
	// +optional
	APIURL *URL `json:"apiURL,omitempty"`

	// The default WeChat API Secret.
	// +optional
	APISecret *v1.SecretKeySelector `json:"apiSecret,omitempty"`

	// The default WeChat API Corporate ID.
	// +optional
	// +kubebuilder:validation:MinLength=1
	APICorpID *string `json:"apiCorpID,omitempty"`
}

// GlobalVictorOpsConfig configures global VictorOps parameters.
type GlobalVictorOpsConfig struct {
	// The default VictorOps API URL.
	//
	// +optional
	APIURL *URL `json:"apiURL,omitempty"`
	// The default VictorOps API Key.
	//
	// +optional
	APIKey *v1.SecretKeySelector `json:"apiKey,omitempty"`
}

// HostPort represents a "host:port" network address.
type HostPort struct {
	// Defines the host's address, it can be a DNS name or a literal IP address.
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
	// Defines the host's port, it can be a literal port number or a port name.
	// +kubebuilder:validation:MinLength=1
	Port string `json:"port"`
}

// HTTPConfig defines a client HTTP configuration.
// See https://prometheus.io/docs/alerting/latest/configuration/#http_config
type HTTPConfig struct {
	// Authorization header configuration for the client.
	// This is mutually exclusive with BasicAuth and is only available starting from Alertmanager v0.22+.
	// +optional
	Authorization *SafeAuthorization `json:"authorization,omitempty"`
	// BasicAuth for the client.
	// This is mutually exclusive with Authorization. If both are defined, BasicAuth takes precedence.
	// +optional
	BasicAuth *BasicAuth `json:"basicAuth,omitempty"`
	// OAuth2 client credentials used to fetch a token for the targets.
	// +optional
	OAuth2 *OAuth2 `json:"oauth2,omitempty"`
	// The secret's key that contains the bearer token to be used by the client
	// for authentication.
	// The secret needs to be in the same namespace as the Alertmanager
	// object and accessible by the Prometheus Operator.
	// +optional
	BearerTokenSecret *v1.SecretKeySelector `json:"bearerTokenSecret,omitempty"`
	// TLS configuration for the client.
	// +optional
	TLSConfig *SafeTLSConfig `json:"tlsConfig,omitempty"`

	ProxyConfig `json:",inline"`

	// FollowRedirects specifies whether the client should follow HTTP 3xx redirects.
	// +optional
	FollowRedirects *bool `json:"followRedirects,omitempty"`
}

// AlertmanagerList is a list of Alertmanagers.
// +k8s:openapi-gen=true
type AlertmanagerList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata
	// More info: https://github.com/kubernetes/community/blob/master/contributors/devel/sig-architecture/api-conventions.md#metadata
	metav1.ListMeta `json:"metadata,omitempty"`
	// List of Alertmanagers
	Items []Alertmanager `json:"items"`
}

// DeepCopyObject implements the runtime.Object interface.
func (l *AlertmanagerList) DeepCopyObject() runtime.Object {
	return l.DeepCopy()
}

// ClusterTLSConfig defines the mutual TLS configuration for the Alertmanager cluster TLS protocol.
// +k8s:openapi-gen=true
type ClusterTLSConfig struct {
	// Server-side configuration for mutual TLS.
	// +required
	ServerTLS WebTLSConfig `json:"server"`
	// Client-side configuration for mutual TLS.
	// +required
	ClientTLS SafeTLSConfig `json:"client"`
}

// URL represents a valid URL
// +kubebuilder:validation:Pattern:="^(http|https)://.+$"
type URL string
