package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ============================================================================
// VaultSecret CRD
// ============================================================================

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=vs
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
// +kubebuilder:printcolumn:name="LastRefresh",type="string",JSONPath=".status.lastRefreshTime"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// VaultSecret is the Schema for the vaultsecrets API.
// VaultSecret defines a reference to a secret stored in HashiCorp Vault.
type VaultSecret struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VaultSecretSpec   `json:"spec,omitempty"`
	Status VaultSecretStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// VaultSecretList contains a list of VaultSecret
type VaultSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VaultSecret `json:"items"`
}

// VaultSecretSpec defines the desired state of VaultSecret
type VaultSecretSpec struct {
	// VaultConnection defines the Vault connection configuration.
	// +kubebuilder:validation:Required
	VaultConnection VaultConnectionConfig `json:"vaultConnection"`

	// Path is the path to the secret in Vault.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Path string `json:"path"`

	// MountPoint is the Vault mount point (KV engine).
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="secret"
	// +optional
	MountPoint *string `json:"mountPoint,omitempty"`

	// Keys defines the key mappings from Vault to the target secret.
	// +kubebuilder:validation:MaxItems=32
	// +optional
	Keys []VaultKeyMapping `json:"keys,omitempty"`

	// Refresh defines the refresh configuration.
	// +optional
	Refresh *VaultRefreshConfig `json:"refresh,omitempty"`

	// Target defines the target Kubernetes secret to create/update.
	// +optional
	Target *VaultTargetConfig `json:"target,omitempty"`
}

// VaultConnectionConfig defines Vault connection configuration
type VaultConnectionConfig struct {
	// Address is the Vault server address.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	Address string `json:"address"`

	// InCluster indicates whether to use in-cluster Vault.
	// +kubebuilder:default=false
	// +optional
	InCluster *bool `json:"inCluster,omitempty"`

	// Namespace is the Vault namespace (Enterprise only).
	// +kubebuilder:validation:MaxLength=253
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// Auth defines the authentication configuration.
	// +kubebuilder:validation:Required
	Auth VaultAuthConfig `json:"auth"`

	// TLS defines the TLS configuration.
	// +optional
	TLS *VaultTLSConfig `json:"tls,omitempty"`
}

// VaultAuthConfig defines Vault authentication configuration
type VaultAuthConfig struct {
	// Kubernetes defines Kubernetes authentication configuration.
	// +optional
	Kubernetes *KubernetesAuthConfig `json:"kubernetes,omitempty"`

	// Token defines token authentication configuration.
	// +optional
	Token *TokenAuthConfig `json:"token,omitempty"`

	// AppRole defines AppRole authentication configuration.
	// +optional
	AppRole *AppRoleAuthConfig `json:"appRole,omitempty"`
}

// KubernetesAuthConfig defines Kubernetes authentication configuration
type KubernetesAuthConfig struct {
	// Role is the Vault role to authenticate with.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Role string `json:"role"`

	// ServiceAccountRef references the ServiceAccount to use for authentication.
	// +optional
	ServiceAccountRef *LocalObjectReference `json:"serviceAccountRef,omitempty"`

	// MountPath is the mount path for Kubernetes auth.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="kubernetes"
	// +optional
	MountPath *string `json:"mountPath,omitempty"`

	// TokenPath is the path to the service account token.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	TokenPath *string `json:"tokenPath,omitempty"`
}

// TokenAuthConfig defines token authentication configuration
type TokenAuthConfig struct {
	// SecretRef references a Secret containing the Vault token.
	// +kubebuilder:validation:Required
	SecretRef SecretObjectReference `json:"secretRef"`

	// TokenKey is the key in the Secret containing the token.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="token"
	// +optional
	TokenKey *string `json:"tokenKey,omitempty"`
}

// AppRoleAuthConfig defines AppRole authentication configuration
type AppRoleAuthConfig struct {
	// RoleID is the AppRole role ID.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	RoleID string `json:"roleId"`

	// SecretIDRef references a Secret containing the AppRole secret ID.
	// +kubebuilder:validation:Required
	SecretIDRef SecretObjectReference `json:"secretIdRef"`

	// SecretIDKey is the key in the Secret containing the secret ID.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="secret-id"
	// +optional
	SecretIDKey *string `json:"secretIdKey,omitempty"`

	// MountPath is the mount path for AppRole auth.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:default="approle"
	// +optional
	MountPath *string `json:"mountPath,omitempty"`
}

// VaultTLSConfig defines TLS configuration for Vault connection
type VaultTLSConfig struct {
	// CACertRef references a Secret containing the CA certificate.
	// +optional
	CACertRef *SecretObjectReference `json:"caCertRef,omitempty"`

	// ClientCertRef references a Secret containing the client certificate.
	// +optional
	ClientCertRef *SecretObjectReference `json:"clientCertRef,omitempty"`

	// ClientKeyRef references a Secret containing the client key.
	// +optional
	ClientKeyRef *SecretObjectReference `json:"clientKeyRef,omitempty"`

	// InsecureSkipVerify skips TLS certificate verification.
	// +kubebuilder:default=false
	// +optional
	InsecureSkipVerify *bool `json:"insecureSkipVerify,omitempty"`

	// ServerName is the expected server name for TLS verification.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	ServerName *string `json:"serverName,omitempty"`
}

// VaultKeyMapping defines a key mapping from Vault to the target secret
type VaultKeyMapping struct {
	// VaultKey is the key in the Vault secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	VaultKey string `json:"vaultKey"`

	// TargetKey is the key in the target Kubernetes secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	TargetKey string `json:"targetKey"`

	// Encoding defines the encoding of the value.
	// +kubebuilder:validation:Enum=None;Base64
	// +kubebuilder:default=None
	// +optional
	Encoding *VaultValueEncoding `json:"encoding,omitempty"`
}

// VaultValueEncoding defines the encoding of a Vault value
// +kubebuilder:validation:Enum=None;Base64
type VaultValueEncoding string

const (
	// VaultValueEncodingNone uses no encoding
	VaultValueEncodingNone VaultValueEncoding = "None"
	// VaultValueEncodingBase64 uses base64 encoding
	VaultValueEncodingBase64 VaultValueEncoding = "Base64"
)

// VaultRefreshConfig defines refresh configuration
type VaultRefreshConfig struct {
	// Enabled indicates whether automatic refresh is enabled.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Interval is the refresh interval.
	// +kubebuilder:default="5m"
	// +optional
	Interval *Duration `json:"interval,omitempty"`

	// JitterPercent is the percentage of jitter to add to the refresh interval.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +kubebuilder:default=10
	// +optional
	JitterPercent *int32 `json:"jitterPercent,omitempty"`
}

// VaultTargetConfig defines the target Kubernetes secret configuration
type VaultTargetConfig struct {
	// Name is the name of the target Secret.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// Namespace is the namespace of the target Secret.
	// If not specified, the namespace of the VaultSecret is used.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// Type is the type of the target Secret.
	// +kubebuilder:validation:Enum=Opaque;kubernetes.io/tls;kubernetes.io/dockerconfigjson
	// +kubebuilder:default=Opaque
	// +optional
	Type *string `json:"type,omitempty"`

	// Labels are labels to add to the target Secret.
	// +kubebuilder:validation:MaxProperties=16
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations are annotations to add to the target Secret.
	// +kubebuilder:validation:MaxProperties=16
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// CreationPolicy defines when to create the target Secret.
	// +kubebuilder:validation:Enum=Owner;Orphan;Merge
	// +kubebuilder:default=Owner
	// +optional
	CreationPolicy *SecretCreationPolicy `json:"creationPolicy,omitempty"`

	// DeletionPolicy defines what to do with the target Secret when the VaultSecret is deleted.
	// +kubebuilder:validation:Enum=Delete;Retain
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy *SecretDeletionPolicy `json:"deletionPolicy,omitempty"`
}

// SecretCreationPolicy defines when to create the target Secret
// +kubebuilder:validation:Enum=Owner;Orphan;Merge
type SecretCreationPolicy string

const (
	// SecretCreationPolicyOwner creates the Secret with owner reference
	SecretCreationPolicyOwner SecretCreationPolicy = "Owner"
	// SecretCreationPolicyOrphan creates the Secret without owner reference
	SecretCreationPolicyOrphan SecretCreationPolicy = "Orphan"
	// SecretCreationPolicyMerge merges with existing Secret
	SecretCreationPolicyMerge SecretCreationPolicy = "Merge"
)

// SecretDeletionPolicy defines what to do with the target Secret when deleted
// +kubebuilder:validation:Enum=Delete;Retain
type SecretDeletionPolicy string

const (
	// SecretDeletionPolicyDelete deletes the target Secret
	SecretDeletionPolicyDelete SecretDeletionPolicy = "Delete"
	// SecretDeletionPolicyRetain retains the target Secret
	SecretDeletionPolicyRetain SecretDeletionPolicy = "Retain"
)

// ============================================================================
// VaultSecret Status
// ============================================================================

// VaultSecretStatus defines the observed state of VaultSecret
type VaultSecretStatus struct {
	Status `json:",inline"`

	// LastRefreshTime is the last time the secret was refreshed from Vault.
	// +optional
	LastRefreshTime *metav1.Time `json:"lastRefreshTime,omitempty"`

	// SecretVersion is the version of the secret in Vault.
	// +kubebuilder:validation:MaxLength=256
	// +optional
	SecretVersion *string `json:"secretVersion,omitempty"`

	// TargetSecretName is the name of the created/updated Kubernetes secret.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	TargetSecretName *string `json:"targetSecretName,omitempty"`

	// TargetSecretNamespace is the namespace of the created/updated Kubernetes secret.
	// +kubebuilder:validation:MaxLength=63
	// +optional
	TargetSecretNamespace *string `json:"targetSecretNamespace,omitempty"`

	// LastVaultError is the last error from Vault, if any.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	LastVaultError *string `json:"lastVaultError,omitempty"`

	// NextRefreshTime is the next scheduled refresh time.
	// +optional
	NextRefreshTime *metav1.Time `json:"nextRefreshTime,omitempty"`
}

func init() {
	SchemeBuilder.Register(&VaultSecret{}, &VaultSecretList{})
}
