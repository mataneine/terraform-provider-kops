package kops

import (
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kops/pkg/apis/kops"
)

func flattenAccessSpec(accessSpec *kops.AccessSpec) []map[string]interface{} {
	data := make(map[string]interface{})
	data["load_balancer"] = flattenLoadBalancerAccessSpec(accessSpec.LoadBalancer)
	if accessSpec.DNS != nil {
		data["dns"] = "true"
	}
	return []map[string]interface{}{data}
}

func flattenAuthorizationSpec(authorizationSpec *kops.AuthorizationSpec) string {
	if authorizationSpec.RBAC != nil {
		return "RBAC"
	}
	return "AlwaysAllow"
}

func flattenCluster(d *schema.ResourceData, cluster *kops.Cluster, instanceGroups *kops.InstanceGroupList) {
	if cluster.Spec.AdditionalPolicies != nil {
		d.Set("additional_policies", *cluster.Spec.AdditionalPolicies)
	}
	d.Set("api", flattenAccessSpec(cluster.Spec.API))
	d.Set("authorization", flattenAuthorizationSpec(cluster.Spec.Authorization))
	d.Set("channel", cluster.Spec.Channel)
	d.Set("cloud_labels", cluster.Spec.CloudLabels)
	d.Set("cloud_provider", cluster.Spec.CloudProvider)
	d.Set("cluster_dnsdomain", cluster.Spec.ClusterDNSDomain)
	d.Set("config_base", cluster.Spec.ConfigBase)
	d.Set("config_store", cluster.Spec.ConfigStore)
	d.Set("creation_timestamp", cluster.ObjectMeta.CreationTimestamp.String())
	d.Set("dns_zone", cluster.Spec.DNSZone)
	if cluster.Spec.Docker != nil {
		d.Set("docker", flattenDockerConfig(cluster.Spec.Docker))
	}
	d.Set("etcd_cluster", flattenEtcdClusterSpec(cluster.Spec.EtcdClusters))
	if cluster.Spec.IAM != nil {
		d.Set("iam", flattenIAMSpec(cluster.Spec.IAM))
	}
	if instanceGroups != nil {
		d.Set("instancegroups", flattenInstanceGroupSpec(instanceGroups))
	}
	d.Set("key_store", cluster.Spec.KeyStore)
	if cluster.Spec.KubeAPIServer != nil {
		d.Set("kube_api_server", flattenKubeAPIServerConfig(cluster.Spec.KubeAPIServer))
	}
	if cluster.Spec.KubeControllerManager != nil {
		d.Set("kube_controller_manager", flattenKubeControllerManagerConfig(cluster.Spec.KubeControllerManager))
	}
	if cluster.Spec.KubeDNS != nil {
		d.Set("kube_dns", flattenKubeDNSConfig(cluster.Spec.KubeDNS))
	}
	if cluster.Spec.KubeProxy != nil {
		d.Set("kube_proxy", flattenKubeProxyConfig(cluster.Spec.KubeProxy))
	}
	if cluster.Spec.KubeScheduler != nil {
		d.Set("kube_scheduler", flattenKubeSchedulerConfig(cluster.Spec.KubeScheduler))
	}
	if cluster.Spec.Kubelet != nil {
		d.Set("kubelet", flattenKubeletConfigSpec(cluster.Spec.Kubelet))
	}
	d.Set("kubernetes_api_access", cluster.Spec.KubernetesAPIAccess)
	d.Set("kubernetes_version", cluster.Spec.KubernetesVersion)
	d.Set("master_internal_name", cluster.Spec.MasterInternalName)
	if cluster.Spec.MasterKubelet != nil {
		d.Set("master_kubelet", flattenKubeletConfigSpec(cluster.Spec.MasterKubelet))
	}
	d.Set("master_public_name", cluster.Spec.MasterPublicName)
	d.Set("name", cluster.ObjectMeta.Name)
	d.Set("network_cidr", cluster.Spec.NetworkCIDR)
	d.Set("network_id", cluster.Spec.NetworkID)
	d.Set("networking", flattenNetworkingSpec(cluster.Spec.Networking))
	d.Set("non_masquerade_cidr", cluster.Spec.NonMasqueradeCIDR)
	d.Set("project", cluster.Spec.Project)
	d.Set("secret_store", cluster.Spec.SecretStore)
	d.Set("service_cluster_iprange", cluster.Spec.ServiceClusterIPRange)
	d.Set("ssh_access", cluster.Spec.SSHAccess)
	d.Set("sshkey_name", cluster.Spec.SSHKeyName)
	d.Set("subnet", flattenClusterSubnetSpec(cluster.Spec.Subnets))
	if cluster.Spec.Topology != nil {
		d.Set("topology", flattenTopologySpec(cluster.Spec.Topology))
	}

	d.SetId(cluster.Name)
}

func flattenClusterSubnetSpec(clusterSubnetSpec []kops.ClusterSubnetSpec) []map[string]interface{} {
	var data []map[string]interface{}
	for _, subnet := range clusterSubnetSpec {
		data = append(data, map[string]interface{}{
			"provider_id": subnet.ProviderID,
			"name":        subnet.Name,
			"cidr":        subnet.CIDR,
			"zone":        subnet.Zone,
			"type":        string(subnet.Type),
		})
	}
	return data
}

func flattenDockerConfig(dockerConfig *kops.DockerConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	if len(dockerConfig.AuthorizationPlugins) > 0 {
		data["authorization_plugins"] = dockerConfig.AuthorizationPlugins
	}
	if dockerConfig.Bridge != nil {
		data["bridge"] = dockerConfig.Bridge
	}
	if dockerConfig.BridgeIP != nil {
		data["bridge_ip"] = dockerConfig.BridgeIP
	}
	if dockerConfig.DataRoot != nil {
		data["data_root"] = dockerConfig.DataRoot
	}
	if len(dockerConfig.DefaultUlimit) > 0 {
		data["default_ulimit"] = dockerConfig.DefaultUlimit
	}
	if dockerConfig.ExecRoot != nil {
		data["exec_root"] = dockerConfig.ExecRoot
	}
	if len(dockerConfig.Hosts) > 0 {
		data["hosts"] = dockerConfig.Hosts
	}
	if dockerConfig.InsecureRegistry != nil {
		data["insecure_registry"] = dockerConfig.InsecureRegistry
	}
	if dockerConfig.IPMasq != nil {
		data["ip_masq"] = strconv.FormatBool(*dockerConfig.IPMasq)
	}
	if dockerConfig.IPTables != nil {
		data["ip_tables"] = strconv.FormatBool(*dockerConfig.IPTables)
	}
	if dockerConfig.LiveRestore != nil {
		data["live_restore"] = strconv.FormatBool(*dockerConfig.LiveRestore)
	}
	if dockerConfig.LogDriver != nil {
		data["log_driver"] = dockerConfig.LogDriver
	}
	if dockerConfig.LogLevel != nil {
		data["log_level"] = dockerConfig.LogLevel
	}
	if len(dockerConfig.LogOpt) > 0 {
		data["log_opt"] = dockerConfig.LogOpt
	}
	if dockerConfig.MTU != nil {
		data["mtu"] = dockerConfig.MTU
	}
	if len(dockerConfig.RegistryMirrors) > 0 {
		data["registry_mirrors"] = dockerConfig.RegistryMirrors
	}
	if dockerConfig.Storage != nil {
		data["storage"] = dockerConfig.Storage
	}
	if dockerConfig.UserNamespaceRemap != "" {
		data["user_namespace_remap"] = dockerConfig.UserNamespaceRemap
	}
	if len(dockerConfig.StorageOpts) > 0 {
		data["storage_opts"] = dockerConfig.StorageOpts
	}
	if dockerConfig.Version != nil {
		data["version"] = dockerConfig.Version
	}
	return []map[string]interface{}{data}
}

func flattenEtcdClusterSpec(etcdClusterSpec []*kops.EtcdClusterSpec) []map[string]interface{} {
	var data []map[string]interface{}

	for _, cluster := range etcdClusterSpec {
		cl := make(map[string]interface{})

		cl["name"] = cluster.Name

		//if cluster.Provider != nil {
		//	cl["provider"] = cluster.Provider
		//}

		// build etcd_members
		var members []map[string]interface{}
		for _, member := range cluster.Members {
			mem := make(map[string]interface{})
			mem["name"] = member.Name
			mem["instance_group"] = *member.InstanceGroup
			if member.VolumeType != nil {
				mem["volume_type"] = *member.VolumeType
			}
			if member.VolumeIops != nil {
				mem["volume_iops"] = int(*member.VolumeIops)
			}
			if member.VolumeSize != nil {
				mem["volume_size"] = int(*member.VolumeSize)
			}
			if member.KmsKeyId != nil {
				mem["kms_key_id"] = *member.KmsKeyId
			}
			if member.EncryptedVolume != nil {
				mem["encrypted_volume"] = strconv.FormatBool(*member.EncryptedVolume)
			}
			members = append(members, mem)
		}
		cl["etcd_member"] = members
		cl["enable_etcd_tls"] = strconv.FormatBool(cluster.EnableEtcdTLS)
		cl["enable_tls_auth"] = strconv.FormatBool(cluster.EnableTLSAuth)
		cl["version"] = cluster.Version
		if cluster.LeaderElectionTimeout != nil {
			cl["leader_election_timeout"] = cluster.LeaderElectionTimeout
		}
		if cluster.HeartbeatInterval != nil {
			cl["heartbeat_interval"] = cluster.HeartbeatInterval
		}
		cl["image"] = cluster.Image
		if cluster.Backups != nil {
			cl["backups"] = []map[string]interface{}{
				{
					"backup_store": cluster.Backups.BackupStore,
					"image":        cluster.Backups.Image,
				},
			}
		}
		if cluster.Manager != nil {
			cl["manager"] = []map[string]interface{}{
				{
					"image": cluster.Manager.Image,
				},
			}
		}

		data = append(data, cl)
	}
	return data
}

func flattenExecContainerAction(execContainerAction *kops.ExecContainerAction) interface{} {
	data := make(map[string]interface{})

	if execContainerAction != nil {
		data["image"] = execContainerAction.Image
		data["command"] = execContainerAction.Command
		data["environment"] = execContainerAction.Environment
	}

	return []map[string]interface{}{data}
}

func flattenFileAssetSpec(fileAssetSpec []kops.FileAssetSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, fa := range fileAssetSpec {
		data["name"] = fa.Name
		data["path"] = fa.Path
		data["content"] = fa.Content
		data["is_base64"] = strconv.FormatBool(fa.IsBase64)
		data["roles"] = fa.Roles
	}

	return []map[string]interface{}{data}
}

func flattenHookSpec(hookSpec []kops.HookSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, hook := range hookSpec {
		data["name"] = hook.Name
		data["disabled"] = strconv.FormatBool(hook.Disabled)
		data["manifest"] = hook.Manifest
		data["before"] = hook.Before
		data["requires"] = hook.Requires

		roles := make([]string, len(hook.Roles))
		for i, role := range hook.Roles {
			roles[i] = string(role)
		}

		data["roles"] = roles
		data["exec_container"] = flattenExecContainerAction(hook.ExecContainer)
	}

	return []map[string]interface{}{data}
}

func flattenIAMProfileSpec(iamProfileSpec *kops.IAMProfileSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	data["profile"] = iamProfileSpec.Profile
	return []map[string]interface{}{data}
}

func flattenIAMSpec(iamSpec *kops.IAMSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	data["allow_container_registry"] = strconv.FormatBool(iamSpec.AllowContainerRegistry)
	data["legacy"] = strconv.FormatBool(iamSpec.Legacy)
	return []map[string]interface{}{data}
}

func flattenInstanceGroupSpec(instanceGroupSpec *kops.InstanceGroupList) []map[string]interface{} {
	var data []map[string]interface{}
	for _, instanceGroup := range instanceGroupSpec.Items {
		ig := map[string]interface{}{}
		ig["name"] = instanceGroup.ObjectMeta.Name
		ig["role"] = instanceGroup.Spec.Role
		ig["machine_type"] = instanceGroup.Spec.MachineType
		ig["image"] = instanceGroup.Spec.Image
		ig["subnets"] = instanceGroup.Spec.Subnets
		ig["zones"] = instanceGroup.Spec.Zones
		if instanceGroup.Spec.IAM != nil {
			ig["iam"] = flattenIAMProfileSpec(instanceGroup.Spec.IAM)
		}
		if instanceGroup.Spec.RootVolumeSize != nil {
			ig["root_volume_size"] = *instanceGroup.Spec.RootVolumeSize
		}
		if instanceGroup.Spec.RootVolumeType != nil {
			ig["root_volume_type"] = *instanceGroup.Spec.RootVolumeType
		}
		if instanceGroup.Spec.RootVolumeIops != nil {
			ig["root_volume_iops"] = *instanceGroup.Spec.RootVolumeIops
		}
		if instanceGroup.Spec.RootVolumeOptimization != nil {
			ig["root_volume_optimization"] = strconv.FormatBool(*instanceGroup.Spec.RootVolumeOptimization)
		}
		if instanceGroup.Spec.MaxPrice != nil {
			ig["max_price"] = *instanceGroup.Spec.MaxPrice
		}		
		if instanceGroup.Spec.MinSize != nil {
			ig["min_size"] = *instanceGroup.Spec.MinSize
		}
		if instanceGroup.Spec.MaxSize != nil {
			ig["max_size"] = *instanceGroup.Spec.MaxSize
		}
		ig["cloud_labels"] = instanceGroup.Spec.CloudLabels
		ig["node_labels"] = instanceGroup.Spec.NodeLabels
		ig["additional_security_groups"] = instanceGroup.Spec.AdditionalSecurityGroups
		ig["additional_user_data"] = flattenUserData(instanceGroup.Spec.AdditionalUserData)
		if instanceGroup.Spec.AssociatePublicIP != nil {
			ig["associate_public_ip"] = strconv.FormatBool(*instanceGroup.Spec.AssociatePublicIP)
		}
		if instanceGroup.Spec.DetailedInstanceMonitoring != nil {
			ig["detailed_instance_monitoring"] = strconv.FormatBool(*instanceGroup.Spec.DetailedInstanceMonitoring)
		}
		ig["external_load_balancer"] = flattenLoadBalancer(instanceGroup.Spec.ExternalLoadBalancers)
		ig["file_asset"] = flattenFileAssetSpec(instanceGroup.Spec.FileAssets)
		ig["hook"] = flattenHookSpec(instanceGroup.Spec.Hooks)
		ig["kubelet"] = flattenKubeletConfigSpec(instanceGroup.Spec.Kubelet)
		ig["taints"] = instanceGroup.Spec.Taints
		data = append(data, ig)
	}
	return data
}

func flattenKubeAPIServerConfig(kubeAPIServerConfig *kops.KubeAPIServerConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["address"] = kubeAPIServerConfig.Address
	if kubeAPIServerConfig.APIServerCount != nil {
		data["api_server_count"] = *kubeAPIServerConfig.APIServerCount
	}
	if kubeAPIServerConfig.AuditLogFormat != nil {
		data["audit_log_format"] = *kubeAPIServerConfig.AuditLogFormat
	}
	if kubeAPIServerConfig.AuditLogMaxAge != nil {
		data["audit_log_max_age"] = *kubeAPIServerConfig.AuditLogMaxAge
	}
	if kubeAPIServerConfig.AuditLogMaxBackups != nil {
		data["audit_log_max_backups"] = *kubeAPIServerConfig.AuditLogMaxBackups
	}
	if kubeAPIServerConfig.AuditLogMaxSize != nil {
		data["audit_log_max_size"] = *kubeAPIServerConfig.AuditLogMaxSize
	}
	if kubeAPIServerConfig.AuditLogPath != nil {
		data["audit_log_path"] = *kubeAPIServerConfig.AuditLogPath
	}
	data["audit_policy_file"] = kubeAPIServerConfig.AuditPolicyFile
	if kubeAPIServerConfig.AuthenticationTokenWebhookCacheTTL != nil {
		data["authentication_token_webhook_cache_ttl"] = kubeAPIServerConfig.AuthenticationTokenWebhookCacheTTL.Duration.String()
	}
	if kubeAPIServerConfig.AuthenticationTokenWebhookConfigFile != nil {
		data["authentication_token_webhook_config_file"] = *kubeAPIServerConfig.AuthenticationTokenWebhookConfigFile
	}
	if kubeAPIServerConfig.AuthorizationMode != nil {
		data["authorization_mode"] = *kubeAPIServerConfig.AuthorizationMode
	}
	if kubeAPIServerConfig.AuthorizationRBACSuperUser != nil {
		data["authorization_rbac_super_user"] = *kubeAPIServerConfig.AuthorizationRBACSuperUser
	}
	if kubeAPIServerConfig.AllowPrivileged != nil {
		data["allow_privileged"] = strconv.FormatBool(*kubeAPIServerConfig.AllowPrivileged)
	}
	if kubeAPIServerConfig.AnonymousAuth != nil {
		data["anonymous_auth"] = strconv.FormatBool(*kubeAPIServerConfig.AnonymousAuth)
	}
	data["basic_auth_file"] = kubeAPIServerConfig.BasicAuthFile
	data["bind_address"] = kubeAPIServerConfig.BindAddress
	data["client_ca_file"] = kubeAPIServerConfig.ClientCAFile
	data["cloud_provider"] = kubeAPIServerConfig.CloudProvider
	data["disable_admission_plugins"] = kubeAPIServerConfig.DisableAdmissionPlugins
	data["enable_admission_plugins"] = kubeAPIServerConfig.EnableAdmissionPlugins
	if kubeAPIServerConfig.EnableAggregatorRouting != nil {
		data["enable_aggregator_routing"] = strconv.FormatBool(*kubeAPIServerConfig.EnableAggregatorRouting)
	}
	if kubeAPIServerConfig.EnableBootstrapAuthToken != nil {
		data["enable_bootstrap_auth_token"] = strconv.FormatBool(*kubeAPIServerConfig.EnableBootstrapAuthToken)
	}
	data["etcd_ca_file"] = kubeAPIServerConfig.EtcdCAFile
	data["etcd_cert_file"] = kubeAPIServerConfig.EtcdCertFile
	data["etcd_key_file"] = kubeAPIServerConfig.EtcdKeyFile
	if kubeAPIServerConfig.EtcdQuorumRead != nil {
		data["etcd_quorum_read"] = strconv.FormatBool(*kubeAPIServerConfig.EtcdQuorumRead)
	}
	data["etcd_servers"] = kubeAPIServerConfig.EtcdServers
	data["etcd_servers_overrides"] = kubeAPIServerConfig.EtcdServersOverrides
	if kubeAPIServerConfig.ExperimentalEncryptionProviderConfig != nil {
		data["experimental_encryption_provider_config"] = *kubeAPIServerConfig.ExperimentalEncryptionProviderConfig
	}
	data["feature_gates"] = kubeAPIServerConfig.FeatureGates
	data["insecure_bind_address"] = kubeAPIServerConfig.InsecureBindAddress
	data["insecure_port"] = int(kubeAPIServerConfig.InsecurePort)
	data["image"] = kubeAPIServerConfig.Image
	data["kubelet_client_certificate"] = kubeAPIServerConfig.KubeletClientCertificate
	data["kubelet_client_key"] = kubeAPIServerConfig.KubeletClientKey
	data["kubelet_preferred_address_types"] = kubeAPIServerConfig.KubeletPreferredAddressTypes
	data["log_level"] = int(kubeAPIServerConfig.LogLevel)
	data["max_requests_inflight"] = int(kubeAPIServerConfig.MaxRequestsInflight)
	if kubeAPIServerConfig.MinRequestTimeout != nil {
		data["mix_request_timeout"] = int(*kubeAPIServerConfig.MinRequestTimeout)
	}
	if kubeAPIServerConfig.OIDCCAFile != nil {
		data["oidc_ca_file"] = *kubeAPIServerConfig.OIDCCAFile
	}
	if kubeAPIServerConfig.OIDCClientID != nil {
		data["oidc_client_id"] = *kubeAPIServerConfig.OIDCClientID
	}
	if kubeAPIServerConfig.OIDCGroupsClaim != nil {
		data["oidc_groups_claim"] = *kubeAPIServerConfig.OIDCGroupsClaim
	}
	if kubeAPIServerConfig.OIDCGroupsPrefix != nil {
		data["oidc_groups_prefix"] = *kubeAPIServerConfig.OIDCGroupsPrefix
	}
	if kubeAPIServerConfig.OIDCIssuerURL != nil {
		data["oidc_issuer_url"] = *kubeAPIServerConfig.OIDCIssuerURL
	}
	if kubeAPIServerConfig.OIDCUsernameClaim != nil {
		data["oidc_username_claim"] = *kubeAPIServerConfig.OIDCUsernameClaim
	}
	if kubeAPIServerConfig.OIDCUsernamePrefix != nil {
		data["oidc_username_prefix"] = *kubeAPIServerConfig.OIDCUsernamePrefix
	}
	if kubeAPIServerConfig.ProxyClientCertFile != nil {
		data["proxy_client_cert_file"] = *kubeAPIServerConfig.ProxyClientCertFile
	}
	if kubeAPIServerConfig.ProxyClientKeyFile != nil {
		data["proxy_client_key_file"] = *kubeAPIServerConfig.ProxyClientKeyFile
	}
	data["requestheader_allowed_names"] = kubeAPIServerConfig.RequestheaderAllowedNames
	data["requestheader_client_ca_file"] = kubeAPIServerConfig.RequestheaderClientCAFile
	data["requestheader_extra_header_prefixes"] = kubeAPIServerConfig.RequestheaderExtraHeaderPrefixes
	data["requestheader_group_headers"] = kubeAPIServerConfig.RequestheaderGroupHeaders
	data["requestheader_username_headers"] = kubeAPIServerConfig.RequestheaderUsernameHeaders
	data["runtime_config"] = kubeAPIServerConfig.RuntimeConfig
	data["secure_port"] = int(kubeAPIServerConfig.SecurePort)
	data["service_cluster_ip_range"] = kubeAPIServerConfig.ServiceClusterIPRange
	data["service_node_port_range"] = kubeAPIServerConfig.ServiceNodePortRange
	if kubeAPIServerConfig.StorageBackend != nil {
		data["storage_backend"] = *kubeAPIServerConfig.StorageBackend
	}
	data["tls_cert_file"] = kubeAPIServerConfig.TLSCertFile
	data["tls_private_key_file"] = kubeAPIServerConfig.TLSPrivateKeyFile
	data["token_auth_file"] = kubeAPIServerConfig.TokenAuthFile
	return []map[string]interface{}{data}
}

func flattenKubeControllerManagerConfig(kubeControllerManagerConfig *kops.KubeControllerManagerConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	if kubeControllerManagerConfig.AllocateNodeCIDRs != nil {
		data["allocate_node_cidrs"] = strconv.FormatBool(*kubeControllerManagerConfig.AllocateNodeCIDRs)
	}
	data["attach_detach_reconcile_sync_period"] = kubeControllerManagerConfig.AttachDetachReconcileSyncPeriod.Duration.String()
	data["cloud_provider"] = kubeControllerManagerConfig.CloudProvider
	data["cluster_cidr"] = kubeControllerManagerConfig.ClusterCIDR
	data["cluster_name"] = kubeControllerManagerConfig.ClusterName
	data["configure_cloud_routes"] = strconv.FormatBool(*kubeControllerManagerConfig.ConfigureCloudRoutes)
	data["feature_gates"] = kubeControllerManagerConfig.FeatureGates
	data["image"] = kubeControllerManagerConfig.Image
	data["leader_election"] = flattenLeaderElectionConfiguration(kubeControllerManagerConfig.LeaderElection)
	data["log_level"] = kubeControllerManagerConfig.LogLevel
	data["use_service_account_credentials"] = strconv.FormatBool(*kubeControllerManagerConfig.UseServiceAccountCredentials)

	if kubeControllerManagerConfig.CIDRAllocatorType != nil {
		data["cidr_allocator_type"] = kubeControllerManagerConfig.CIDRAllocatorType
	}
	if kubeControllerManagerConfig.HorizontalPodAutoscalerDownscaleDelay != nil {
		data["horizontal_pod_autoscaler_downscale_delay"] = kubeControllerManagerConfig.HorizontalPodAutoscalerDownscaleDelay.Duration.String()
	}
	if kubeControllerManagerConfig.HorizontalPodAutoscalerSyncPeriod != nil {
		data["horizontal_pod_autoscaler_sync_period"] = kubeControllerManagerConfig.HorizontalPodAutoscalerSyncPeriod.Duration.String()
	}
	if kubeControllerManagerConfig.HorizontalPodAutoscalerUpscaleDelay != nil {
		data["horizontal_pod_autoscaler_upscale_delay"] = kubeControllerManagerConfig.HorizontalPodAutoscalerUpscaleDelay.Duration.String()
	}
	if kubeControllerManagerConfig.HorizontalPodAutoscalerUseRestClients != nil {
		data["horizontal_pod_autoscaler_use_rest_clients"] = strconv.FormatBool(*kubeControllerManagerConfig.HorizontalPodAutoscalerUseRestClients)
	}
	if kubeControllerManagerConfig.Master != "" {
		data["master"] = kubeControllerManagerConfig.Master
	}
	if kubeControllerManagerConfig.NodeMonitorGracePeriod != nil {
		data["node_monitor_grace_period"] = kubeControllerManagerConfig.NodeMonitorGracePeriod.Duration.String()
	}
	if kubeControllerManagerConfig.NodeMonitorPeriod != nil {
		data["node_monitor_period"] = kubeControllerManagerConfig.NodeMonitorPeriod.Duration.String()
	}
	if kubeControllerManagerConfig.PodEvictionTimeout != nil {
		data["pod_eviction_timeout"] = kubeControllerManagerConfig.PodEvictionTimeout.Duration.String()
	}
	if kubeControllerManagerConfig.RootCAFile != "" {
		data["root_ca_file"] = kubeControllerManagerConfig.RootCAFile
	}
	if kubeControllerManagerConfig.ServiceAccountPrivateKeyFile != "" {
		data["service_account_private_key_file"] = kubeControllerManagerConfig.ServiceAccountPrivateKeyFile
	}
	if kubeControllerManagerConfig.TerminatedPodGCThreshold != nil {
		data["terminated_pod_gc_threshold"] = int(*kubeControllerManagerConfig.TerminatedPodGCThreshold)
	}
	return []map[string]interface{}{data}
}

func flattenKubeDNSConfig(kubeDNSConfig *kops.KubeDNSConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["cache_max_concurrent"] = kubeDNSConfig.CacheMaxConcurrent
	data["cache_max_size"] = kubeDNSConfig.CacheMaxSize
	data["domain"] = kubeDNSConfig.Domain
	data["image"] = kubeDNSConfig.Image
	data["provider"] = kubeDNSConfig.Provider
	data["replicas"] = kubeDNSConfig.Replicas
	data["server_ip"] = kubeDNSConfig.ServerIP
	data["stub_domains"] = flattenStubDomains(kubeDNSConfig.StubDomains)
	data["upstream_nameservers"] = kubeDNSConfig.UpstreamNameservers
	return []map[string]interface{}{data}
}

func flattenKubeletConfigSpec(kubeletConfigSpec *kops.KubeletConfigSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	if kubeletConfigSpec != nil {
		data["api_servers"] = kubeletConfigSpec.APIServers
		data["authorization_mode"] = kubeletConfigSpec.AuthorizationMode
		if kubeletConfigSpec.AllowPrivileged != nil {
			data["allow_privileged"] = strconv.FormatBool(*kubeletConfigSpec.AllowPrivileged)
		}
		if kubeletConfigSpec.AnonymousAuth != nil {
			data["anonymous_auth"] = strconv.FormatBool(*kubeletConfigSpec.AnonymousAuth)
		}
		if kubeletConfigSpec.AuthenticationTokenWebhook != nil {
			data["authentication_token_webhook"] = strconv.FormatBool(*kubeletConfigSpec.AuthenticationTokenWebhook)
		}
		if kubeletConfigSpec.AuthenticationTokenWebhookCacheTTL != nil {
			data["authentication_token_webhook_cache_ttl"] = kubeletConfigSpec.AuthenticationTokenWebhookCacheTTL.Duration.String()
		}
		// if spec.BabysitDaemons != nil {
		// 	data["babysit_daemons"] = strconv.FormatBool(*spec.BabysitDaemons)
		// }
		data["bootstrap_kubeconfig"] = kubeletConfigSpec.BootstrapKubeconfig
		data["cgroup_root"] = kubeletConfigSpec.CgroupRoot
		data["client_ca_file"] = kubeletConfigSpec.ClientCAFile
		data["cloud_provider"] = kubeletConfigSpec.CloudProvider
		data["cluster_dns"] = kubeletConfigSpec.ClusterDNS
		data["cluster_domain"] = kubeletConfigSpec.ClusterDomain
		if kubeletConfigSpec.ConfigureCBR0 != nil {
			data["configure_cbr0"] = strconv.FormatBool(*kubeletConfigSpec.ConfigureCBR0)
		}
		if kubeletConfigSpec.DockerDisableSharedPID != nil {
			data["docker_disable_shared_pid"] = strconv.FormatBool(*kubeletConfigSpec.DockerDisableSharedPID)
		}
		if kubeletConfigSpec.EnableCustomMetrics != nil {
			data["enable_custom_metrics"] = strconv.FormatBool(*kubeletConfigSpec.EnableCustomMetrics)
		}
		if kubeletConfigSpec.EnableDebuggingHandlers != nil {
			data["enable_debugging_handlers"] = strconv.FormatBool(*kubeletConfigSpec.EnableDebuggingHandlers)
		}
		data["enforce_node_allocatable"] = kubeletConfigSpec.EnforceNodeAllocatable
		if kubeletConfigSpec.EvictionHard != nil {
			data["eviction_hard"] = *kubeletConfigSpec.EvictionHard
		}
		data["eviction_max_pod_grace_period"] = kubeletConfigSpec.EvictionMaxPodGracePeriod
		data["eviction_minimum_reclaim"] = kubeletConfigSpec.EvictionMinimumReclaim
		if kubeletConfigSpec.EvictionPressureTransitionPeriod != nil {
			data["eviction_pressure_transition_period"] = kubeletConfigSpec.EvictionPressureTransitionPeriod.Duration.String()
		}

		data["eviction_soft"] = kubeletConfigSpec.EvictionSoft
		data["eviction_soft_grace_period"] = kubeletConfigSpec.EvictionSoftGracePeriod
		data["experimental_allowed_unsafe_sysctls"] = kubeletConfigSpec.ExperimentalAllowedUnsafeSysctls
		if kubeletConfigSpec.FailSwapOn != nil {
			data["fail_swap_on"] = strconv.FormatBool(*kubeletConfigSpec.FailSwapOn)
		}

		data["feature_gates"] = kubeletConfigSpec.FeatureGates
		data["hairpin_mode"] = kubeletConfigSpec.HairpinMode
		data["hostname_override"] = kubeletConfigSpec.HostnameOverride
		if kubeletConfigSpec.ImageGCHighThresholdPercent != nil {
			data["image_gc_high_threshold_percent"] = int(*kubeletConfigSpec.ImageGCHighThresholdPercent)
		}
		if kubeletConfigSpec.ImageGCLowThresholdPercent != nil {
			data["image_gc_low_threshold_percent"] = int(*kubeletConfigSpec.ImageGCLowThresholdPercent)
		}
		if kubeletConfigSpec.ImagePullProgressDeadline != nil {
			data["image_pull_progress_deadline"] = kubeletConfigSpec.ImagePullProgressDeadline.Duration.String()
		}
		data["kubeconfig_path"] = kubeletConfigSpec.KubeconfigPath
		data["kubelet_cgroups"] = kubeletConfigSpec.KubeletCgroups
		data["kube_reserved"] = kubeletConfigSpec.KubeReserved
		data["kube_reserved_cgroup"] = kubeletConfigSpec.KubeReservedCgroup
		if kubeletConfigSpec.LogLevel != nil {
			data["log_level"] = int(*kubeletConfigSpec.LogLevel)
		}
		if kubeletConfigSpec.MaxPods != nil {
			data["max_pods"] = int(*kubeletConfigSpec.MaxPods)
		}
		if kubeletConfigSpec.NetworkPluginMTU != nil {
			data["network_plugin_mtu"] = int(*kubeletConfigSpec.NetworkPluginMTU)
		}

		data["network_plugin_name"] = kubeletConfigSpec.NetworkPluginName

		data["node_labels"] = kubeletConfigSpec.NodeLabels
		if kubeletConfigSpec.NodeStatusUpdateFrequency != nil {
			data["node_status_update_frequency"] = kubeletConfigSpec.NodeStatusUpdateFrequency.Duration.String()
		}
		data["non_masquerade_cidr"] = kubeletConfigSpec.NonMasqueradeCIDR
		data["nvidia_gpus"] = kubeletConfigSpec.NvidiaGPUs

		data["pod_cidr"] = kubeletConfigSpec.PodCIDR
		data["pod_infra_container_image"] = kubeletConfigSpec.PodInfraContainerImage
		data["pod_manifest_path"] = kubeletConfigSpec.PodManifestPath
		if kubeletConfigSpec.ReadOnlyPort != nil {
			data["read_only_port"] = int(*kubeletConfigSpec.ReadOnlyPort)
		}
		if kubeletConfigSpec.ReconcileCIDR != nil {
			data["reconcile_cidr"] = strconv.FormatBool(*kubeletConfigSpec.ReconcileCIDR)
		}
		if kubeletConfigSpec.RegisterNode != nil {
			data["register_node"] = strconv.FormatBool(*kubeletConfigSpec.RegisterNode)
		}
		if kubeletConfigSpec.RegisterSchedulable != nil {
			data["register_schedulable"] = strconv.FormatBool(*kubeletConfigSpec.RegisterSchedulable)
		}
		// if spec.RequireKubeconfig != nil {
		// 	data["require_kubeconfig"] = strconv.FormatBool(*spec.RequireKubeconfig)
		// }
		if kubeletConfigSpec.ResolverConfig != nil {
			data["resolver_config"] = *kubeletConfigSpec.ResolverConfig
		}
		data["root_dir"] = kubeletConfigSpec.RootDir
		if kubeletConfigSpec.RuntimeRequestTimeout != nil {
			data["runtime_request_timeout"] = kubeletConfigSpec.RuntimeRequestTimeout.Duration.String()
		}
		data["runtime_cgroups"] = kubeletConfigSpec.RuntimeCgroups
		if kubeletConfigSpec.SeccompProfileRoot != nil {
			data["seccomp_profile_root"] = *kubeletConfigSpec.SeccompProfileRoot
		}
		if kubeletConfigSpec.SerializeImagePulls != nil {
			data["serialize_image_pulls"] = strconv.FormatBool(*kubeletConfigSpec.SerializeImagePulls)
		}
		if kubeletConfigSpec.StreamingConnectionIdleTimeout != nil {
			data["streaming_connection_idle_timeout"] = kubeletConfigSpec.StreamingConnectionIdleTimeout.Duration.String()
		}
		data["system_cgroups"] = kubeletConfigSpec.SystemCgroups
		data["system_reserved"] = kubeletConfigSpec.SystemReserved
		data["system_reserved_cgroup"] = kubeletConfigSpec.SystemReservedCgroup
		data["taints"] = kubeletConfigSpec.Taints
		data["tls_cert_file"] = kubeletConfigSpec.TLSCertFile
		data["tls_private_key_file"] = kubeletConfigSpec.TLSPrivateKeyFile
		data["volume_plugin_directory"] = kubeletConfigSpec.VolumePluginDirectory
		if kubeletConfigSpec.VolumeStatsAggPeriod != nil {
			data["volume_stats_agg_period"] = kubeletConfigSpec.VolumeStatsAggPeriod.Duration.String()
		}
	}

	return []map[string]interface{}{data}
}

func flattenKubeProxyConfig(kubeProxyConfig *kops.KubeProxyConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["bind_address"] = kubeProxyConfig.BindAddress
	if kubeProxyConfig.ConntrackMaxPerCore != nil {
		data["conntrack_max_per_core"] = kubeProxyConfig.ConntrackMaxPerCore
	}
	if kubeProxyConfig.ConntrackMin != nil {
		data["conntrack_min"] = kubeProxyConfig.ConntrackMin
	}
	data["cluster_cidr"] = kubeProxyConfig.ClusterCIDR
	data["cpu_limit"] = kubeProxyConfig.CPULimit
	data["cpu_request"] = kubeProxyConfig.CPURequest
	if kubeProxyConfig.Enabled != nil {
		data["enabled"] = strconv.FormatBool(*kubeProxyConfig.Enabled)
	}
	data["feature_gates"] = kubeProxyConfig.FeatureGates
	data["hostname_override"] = kubeProxyConfig.HostnameOverride
	data["image"] = kubeProxyConfig.Image
	data["log_level"] = kubeProxyConfig.LogLevel
	data["master"] = kubeProxyConfig.Master
	data["memory_limit"] = kubeProxyConfig.MemoryLimit
	data["memory_request"] = kubeProxyConfig.MemoryRequest
	data["proxy_mode"] = kubeProxyConfig.ProxyMode
	return []map[string]interface{}{data}
}

func flattenKubeSchedulerConfig(kubeSchedulerConfig *kops.KubeSchedulerConfig) []map[string]interface{} {
	data := make(map[string]interface{})
	data["feature_gates"] = kubeSchedulerConfig.FeatureGates
	data["image"] = kubeSchedulerConfig.Image
	if kubeSchedulerConfig.LeaderElection != nil {
		data["leader_election"] = flattenLeaderElectionConfiguration(kubeSchedulerConfig.LeaderElection)
	}
	data["log_level"] = int(kubeSchedulerConfig.LogLevel)
	data["master"] = kubeSchedulerConfig.Master
	if kubeSchedulerConfig.UsePolicyConfigMap != nil {
		data["use_policy_config_map"] = strconv.FormatBool(*kubeSchedulerConfig.UsePolicyConfigMap)
	}
	return []map[string]interface{}{data}
}

func flattenLeaderElectionConfiguration(leaderElectionConfiguration *kops.LeaderElectionConfiguration) []map[string]interface{} {
	data := make(map[string]interface{})
	if leaderElectionConfiguration.LeaderElect != nil {
		data["leader_elect"] = strconv.FormatBool(*leaderElectionConfiguration.LeaderElect)
	}
	return []map[string]interface{}{data}
}

func flattenLoadBalancer(loadBalancer []kops.LoadBalancer) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, balancer := range loadBalancer {
		data["load_balancer_name"] = *balancer.LoadBalancerName
		data["target_group_arn"] = *balancer.TargetGroupARN
	}

	return []map[string]interface{}{data}
}

func flattenLoadBalancerAccessSpec(loadBalancerAccessSpec *kops.LoadBalancerAccessSpec) []map[string]interface{} {
	data := make(map[string]interface{})
	data["type"] = loadBalancerAccessSpec.Type
	if loadBalancerAccessSpec.IdleTimeoutSeconds != nil {
		data["idle_timeout_seconds"] = loadBalancerAccessSpec.IdleTimeoutSeconds
	}
	if len(loadBalancerAccessSpec.AdditionalSecurityGroups) > 0 {
		data["additional_security_groups"] = loadBalancerAccessSpec.AdditionalSecurityGroups
	}
	data["use_for_internal_api"] = strconv.FormatBool(loadBalancerAccessSpec.UseForInternalApi)
	if loadBalancerAccessSpec.SSLCertificate != "" {
		data["ssl_certificate"] = loadBalancerAccessSpec.SSLCertificate
	}
	return []map[string]interface{}{data}
}

func flattenNetworkingSpec(networkingSpec *kops.NetworkingSpec) []map[string]interface{} {
	data := make(map[string]interface{})

	if networkingSpec.Classic != nil {
		data["name"] = "classic"
	}
	if networkingSpec.Kubenet != nil {
		data["name"] = "kubenet"
	}
	if networkingSpec.External != nil {
		data["name"] = "external"
	}
	if networkingSpec.CNI != nil {
		data["name"] = "cni"
	}
	if networkingSpec.Kopeio != nil {
		data["name"] = "kopeio"
	}
	if networkingSpec.Weave != nil {
		data["name"] = "weave"
	}
	if networkingSpec.Flannel != nil {
		data["name"] = "flannel"
	}
	if networkingSpec.Calico != nil {
		data["name"] = "calico"
	}
	if networkingSpec.Canal != nil {
		data["name"] = "canal"
	}
	if networkingSpec.Kuberouter != nil {
		data["name"] = "kuberouter"
	}
	if networkingSpec.Romana != nil {
		data["name"] = "romana"
	}
	if networkingSpec.AmazonVPC != nil {
		data["name"] = "amazonvpc"
	}
	if networkingSpec.Cilium != nil {
		data["name"] = "cilium"
	}

	return []map[string]interface{}{data}
}

func flattenObjectMeta(d *schema.ResourceData, objectMeta v1.ObjectMeta) {
	d.Set("name", objectMeta.Name)
	d.Set("creation_timestamp", objectMeta.CreationTimestamp.String())
}

func flattenStubDomains(stubDomains map[string][]string) map[string]interface{} {
	data := make(map[string]interface{})
	for key, val := range stubDomains {
		data[key] = strings.Join(val, ",")
	}
	return data
}

func flattenTopologySpec(topologySpec *kops.TopologySpec) []map[string]interface{} {
	data := make(map[string]interface{})
	data["masters"] = topologySpec.Masters
	data["nodes"] = topologySpec.Nodes
	if topologySpec.Bastion != nil {
		data["bastion"] = []map[string]interface{}{
			{
				"bastion_public_name":  topologySpec.Bastion.BastionPublicName,
				"idle_timeout_seconds": int(*topologySpec.Bastion.IdleTimeoutSeconds),
			},
		}
	}
	data["dns"] = []map[string]interface{}{
		{
			"type": topologySpec.DNS.Type,
		},
	}
	return []map[string]interface{}{data}
}

func flattenUserData(userData []kops.UserData) []map[string]interface{} {
	data := make(map[string]interface{})

	for _, u := range userData {
		data["name"] = u.Name
		data["type"] = u.Type
		data["content"] = u.Content
	}

	return []map[string]interface{}{data}
}
