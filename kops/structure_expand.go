package kops

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kops/pkg/apis/kops"
)

func expandAWSConfig(d *schema.ResourceData) {
	awsList := d.Get("aws").(*schema.Set).List()
	if len(awsList) == 1 {
		aws := awsList[0].(map[string]interface{})
		if aws["access_key"].(string) != "" {
			os.Setenv("AWS_ACCESS_KEY_ID", aws["access_key"].(string))
		}
		if aws["secret_key"].(string) != "" {
			os.Setenv("AWS_SECRET_ACCESS_KEY", aws["secret_key"].(string))
		}
		if aws["profile"].(string) != "" {
			os.Setenv("AWS_PROFILE", aws["profile"].(string))
		}
		if aws["shared_credentials_file"].(string) != "" {
			os.Setenv("AWS_SHARED_CREDENTIALS_FILE", aws["shared_credentials_file"].(string))
		}
		if aws["token"].(string) != "" {
			os.Setenv("AWS_SESSION_TOKEN", aws["token"].(string))
		}
		if aws["region"].(string) != "" {
			os.Setenv("AWS_REGION", aws["region"].(string))
		}

		assumeRoleList := aws["assume_role"].([]interface{})
		if len(assumeRoleList) == 1 {
			assumeRole := assumeRoleList[0].(map[string]interface{})

			if assumeRole["role_arn"].(string) != "" {
				// Initial credentials loaded from SDK's default credential chain. Such as
				// the environment, shared credentials (~/.aws/credentials), or EC2 Instance
				// Role. These credentials will be used to to make the STS Assume Role API.
				sess := session.Must(session.NewSession())

				// Create the credentials from AssumeRoleProvider to assume the role
				// referenced by the "myRoleARN" ARN.
				creds, err := stscreds.NewCredentials(sess, assumeRole["role_arn"].(string), func(p *stscreds.AssumeRoleProvider) {
					if assumeRole["session_name"].(string) != "" {
						p.RoleSessionName = assumeRole["session_name"].(string)
					}
					if assumeRole["external_id"].(string) != "" {
						p.ExternalID = expandString(assumeRole["external_id"].(string))
					}
					if assumeRole["policy"].(string) != "" {
						p.Policy = expandString(assumeRole["policy"].(string))
					}
					// log.Printf("[INFO] assume_role set: (ARN: %q, SessionID: %q, ExternalID: %q, Policy: %q)", p.RoleARN, p.RoleSessionName, *p.ExternalID, *p.Policy)
				}).Get()
				if err != nil {
					log.Printf("[ERROR] assume_role get: %s", err)
				}
				os.Setenv("AWS_ACCESS_KEY_ID", creds.AccessKeyID)
				os.Setenv("AWS_SECRET_ACCESS_KEY", creds.SecretAccessKey)
				os.Setenv("AWS_SESSION_TOKEN", creds.SessionToken)
			}
		}
	}
}

func expandAccessSpec(data []interface{}) *kops.AccessSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		accessSpec := &kops.AccessSpec{
			LoadBalancer: expandLoadBalancerAccessSpec(d["load_balancer"].([]interface{})),
		}
		dns := *expandBool(d["dns"])
		if dns {
			accessSpec.DNS = &kops.DNSAccessSpec{}
		}
		return accessSpec
	}
	return nil
}

func expandBastionSpec(data []interface{}) *kops.BastionSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		bastion := &kops.BastionSpec{
			BastionPublicName: d["bastion_public_name"].(string),
		}
		if d["idle_timeout_seconds"].(string) != "" {
			bastion.IdleTimeoutSeconds = expandInt64(d["idle_timeout_seconds"])
		}
		return bastion
	}
	return nil
}

func expandCluster(d *schema.ResourceData) *kops.Cluster {
	cluster := &kops.Cluster{
		ObjectMeta: expandObjectMeta(d.Get("name").(string), d.Get("creation_timestamp").(string)),
	}

	if v, ok := d.GetOk("additional_policies"); ok {
		additionalPolicies := expandStringMap(v)
		cluster.Spec.AdditionalPolicies = &additionalPolicies
	}

	if v, ok := d.GetOk("api"); ok {
		cluster.Spec.API = expandAccessSpec(v.([]interface{}))
	}
	cluster.Spec.Authorization = stringToAuthorizationSpec(d.Get("authorization").(string))
	cluster.Spec.Channel = d.Get("channel").(string)
	if v, ok := d.GetOk("cloud_labels"); ok {
		cluster.Spec.CloudLabels = expandStringMap(v)
	}
	cluster.Spec.CloudProvider = d.Get("cloud_provider").(string)
	cluster.Spec.ClusterDNSDomain = d.Get("cluster_dnsdomain").(string)
	cluster.Spec.ConfigBase = d.Get("config_base").(string)
	cluster.Spec.ConfigStore = d.Get("config_store").(string)
	cluster.Spec.DNSZone = d.Get("dns_zone").(string)
	if v, ok := d.GetOk("docker"); ok {
		cluster.Spec.Docker = expandDockerConfig(v.([]interface{}))
	}
	if v, ok := d.GetOk("etcd_cluster"); ok {
		cluster.Spec.EtcdClusters = expandEtcdClusterSpec(v.([]interface{}))
	}
	if v, ok := d.GetOk("iam"); ok {
		cluster.Spec.IAM = expandIAMSpec(v.([]interface{}))
	}
	cluster.Spec.KeyStore = d.Get("key_store").(string)
	if v, ok := d.GetOk("kube_api_server"); ok {
		cluster.Spec.KubeAPIServer = expandKubeAPIServerConfig(v.([]interface{}))
	}
	if v, ok := d.GetOk("kube_controller_manager"); ok {
		cluster.Spec.KubeControllerManager = expandKubeControllerManagerConfig(v.([]interface{}))
	}
	if v, ok := d.GetOk("kube_dns"); ok {
		cluster.Spec.KubeDNS = expandKubeDNSConfig(v.([]interface{}))
	}
	if v, ok := d.GetOk("kube_proxy"); ok {
		cluster.Spec.KubeProxy = expandKubeProxyConfig(v.([]interface{}))
	}
	if v, ok := d.GetOk("kube_scheduler"); ok {
		cluster.Spec.KubeScheduler = expandKubeSchedulerConfig(v.([]interface{}))
	}
	if v, ok := d.GetOk("kubelet"); ok {
		cluster.Spec.Kubelet = expandKubeletConfigSpec(v.([]interface{}))
	}
	if v, ok := d.GetOk("kubernetes_api_access"); ok {
		cluster.Spec.KubernetesAPIAccess = expandStringSlice(v)
	}
	cluster.Spec.KubernetesVersion = d.Get("kubernetes_version").(string)
	cluster.Spec.MasterInternalName = d.Get("master_internal_name").(string)
	if v, ok := d.GetOk("master_kubelet"); ok {
		cluster.Spec.MasterKubelet = expandKubeletConfigSpec(v.([]interface{}))
	}
	cluster.Spec.MasterPublicName = d.Get("master_public_name").(string)
	cluster.Spec.NetworkCIDR = d.Get("network_cidr").(string)
	cluster.Spec.NetworkID = d.Get("network_id").(string)
	if v, ok := d.GetOk("networking"); ok {
		cluster.Spec.Networking = expandNetworkingSpec(v.([]interface{}))
	}
	cluster.Spec.NonMasqueradeCIDR = d.Get("non_masquerade_cidr").(string)
	cluster.Spec.Project = d.Get("project").(string)
	cluster.Spec.SecretStore = d.Get("secret_store").(string)
	if v, ok := d.GetOk("ssh_access"); ok {
		cluster.Spec.SSHAccess = expandStringSlice(v)
	}
	if v, ok := d.GetOk("subnet"); ok {
		cluster.Spec.Subnets = expandClusterSubnetSpec(v.([]interface{}))
	}
	cluster.Spec.ServiceClusterIPRange = d.Get("service_cluster_iprange").(string)
	cluster.Spec.SSHKeyName = expandString(d.Get("sshkey_name"))
	if v, ok := d.GetOk("topology"); ok {
		cluster.Spec.Topology = expandTopologySpec(v.([]interface{}))
	}

	j, _ := json.Marshal(cluster)
	log.Printf("[DEBUG] Cluster: %s", string(j))

	return cluster
}

func expandClusterSubnetSpec(data []interface{}) []kops.ClusterSubnetSpec {
	var subnets []kops.ClusterSubnetSpec
	for _, s := range data {
		conv := s.(map[string]interface{})
		subnets = append(subnets, kops.ClusterSubnetSpec{
			ProviderID: conv["provider_id"].(string),
			Name:       conv["name"].(string),
			CIDR:       conv["cidr"].(string),
			Zone:       conv["zone"].(string),
			Type:       kops.SubnetType(conv["type"].(string)),
		})
	}
	return subnets
}

func expandDNSSpec(data []interface{}) *kops.DNSSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		return &kops.DNSSpec{
			Type: kops.DNSType(d["type"].(string)),
		}
	}
	return nil
}

func expandDockerConfig(data []interface{}) *kops.DockerConfig {
	if len(data) > 0 {
		conv := data[0].(map[string]interface{})
		config := &kops.DockerConfig{
			UserNamespaceRemap: conv["user_namespace_remap"].(string),
		}
		if len(conv["authorization_plugins"].([]interface{})) > 0 {
			config.AuthorizationPlugins = expandStringSlice(conv["authorization_plugins"])
		}
		if conv["bridge"].(string) != "" {
			config.Bridge = expandString(conv["bridge"])
		}
		if conv["bridge_ip"].(string) != "" {
			config.BridgeIP = expandString(conv["bridge_ip"])
		}
		if conv["data_root"].(string) != "" {
			config.DataRoot = expandString(conv["data_root"])
		}
		if len(conv["default_ulimit"].([]interface{})) > 0 {
			config.DefaultUlimit = expandStringSlice(conv["default_ulimit"])
		}
		if conv["exec_root"].(string) != "" {
			config.ExecRoot = expandString(conv["exec_root"])
		}
		if len(conv["hosts"].([]interface{})) > 0 {
			config.Hosts = expandStringSlice(conv["hosts"])
		}
		if conv["insecure_registry"].(string) != "" {
			config.InsecureRegistry = expandString(conv["insecure_registry"])
		}
		if conv["ip_masq"].(string) != "" {
			config.IPMasq = expandBool(conv["ip_masq"])
		}
		if conv["ip_tables"].(string) != "" {
			config.IPTables = expandBool(conv["ip_tables"])
		}
		if conv["live_restore"].(string) != "" {
			config.LiveRestore = expandBool(conv["live_restore"])
		}
		if conv["log_driver"].(string) != "" {
			config.LogDriver = expandString(conv["log_driver"])
		}
		if conv["log_level"].(string) != "" {
			config.LogLevel = expandString(conv["log_level"])
		}
		if len(conv["log_opt"].([]interface{})) > 0 {
			config.LogOpt = expandStringSlice(conv["log_opt"])
		}
		if conv["mtu"].(string) != "" {
			config.MTU = expandInt32(conv["mtu"])
		}
		if len(conv["registry_mirrors"].([]interface{})) > 0 {
			config.RegistryMirrors = expandStringSlice(conv["registry_mirrors"])
		}
		if conv["storage"].(string) != "" {
			config.Storage = expandString(conv["storage"])
		}
		if len(conv["storage_opts"].([]interface{})) > 0 {
			config.StorageOpts = expandStringSlice(conv["storage_opts"])
		}
		if conv["version"].(string) != "" {
			config.Version = expandString(conv["version"])
		}
		return config
	}
	return nil
}

func expandEtcdBackupSpec(data []interface{}) *kops.EtcdBackupSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		backup := &kops.EtcdBackupSpec{}
		backup.BackupStore = d["backup_store"].(string)
		backup.Image = d["image"].(string)
		return backup
	}
	return nil
}

func expandEtcdClusterSpec(data []interface{}) []*kops.EtcdClusterSpec {
	var clusters []*kops.EtcdClusterSpec

	for _, cluster := range data {
		top := cluster.(map[string]interface{})

		spec := &kops.EtcdClusterSpec{
			Name:    top["name"].(string),
			Image:   top["image"].(string),
			Version: top["version"].(string),
			Members: expandEtcdMemberSpec(top["etcd_member"].([]interface{})),
			Manager: expandEtcdManagerSpec(top["manager"].([]interface{})),
			Backups: expandEtcdBackupSpec(top["backups"].([]interface{})),
		}

		if top["enable_etcd_tls"].(string) != "" {
			spec.EnableEtcdTLS = *expandBool(top["enable_etcd_tls"])
		}
		if top["enable_tls_auth"].(string) != "" {
			spec.EnableTLSAuth = *expandBool(top["enable_tls_auth"])
		}
		clusters = append(clusters, spec)
	}

	return clusters
}

func expandEtcdManagerSpec(data []interface{}) *kops.EtcdManagerSpec {
	if len(data) > 0 {
		manager := &kops.EtcdManagerSpec{}
		if len(data) > 0 {
			d := data[0].(map[string]interface{})
			manager.Image = d["image"].(string)
		}
		return manager
	}
	return nil
}

func expandEtcdMemberSpec(data []interface{}) []*kops.EtcdMemberSpec {
	var members []*kops.EtcdMemberSpec

	for _, d := range data {
		member := d.(map[string]interface{})
		spec := &kops.EtcdMemberSpec{
			Name:          member["name"].(string),
			InstanceGroup: expandString(member["instance_group"]),
		}
		if member["encrypted_volume"].(string) != "" {
			spec.EncryptedVolume = expandBool(member["encrypted_volume"])
		}
		kmsKeyID := member["kms_key_id"].(string)
		if kmsKeyID != "" {
			spec.KmsKeyId = &kmsKeyID
		}
		volumeType := member["volume_type"].(string)
		if volumeType != "" {
			spec.VolumeType = &volumeType
		}
		if member["volume_iops"].(string) != "" {
			spec.VolumeIops = expandInt32(member["volume_iops"].(string))
		}
		if member["volume_size"].(string) != "" {
			spec.VolumeSize = expandInt32(member["volume_size"].(string))
		}

		members = append(members, spec)
	}

	return members
}

func expandExecContainerAction(data []interface{}) *kops.ExecContainerAction {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		exec := &kops.ExecContainerAction{
			Image:       d["image"].(string),
			Command:     expandStringSlice(d["command"]),
			Environment: expandStringMap(d["environment"]),
		}

		return exec
	}
	return nil
}

func expandFileAssetSpec(data []interface{}) []kops.FileAssetSpec {
	var fileAssets []kops.FileAssetSpec

	for _, d := range data {
		if d != nil {
			fas := d.(map[string]interface{})
			name := fas["name"].(string)
			path := fas["path"].(string)
			content := fas["content"].(string)
			rolesString := expandStringSlice(fas["roles"])
			roles := make([]kops.InstanceGroupRole, len(rolesString))

			for i, role := range rolesString {
				roles[i] = kops.InstanceGroupRole(role)
			}
			spec := kops.FileAssetSpec{
				Name:    name,
				Path:    path,
				Content: content,
				Roles:   roles,
			}
			if fas["is_base64"].(string) != "" {
				spec.IsBase64 = *expandBool(fas["is_base64"])
			}

			fileAssets = append(fileAssets, spec)
		}
	}

	return fileAssets
}

func expandHookSpec(data []interface{}) []kops.HookSpec {
	var hooks []kops.HookSpec

	for _, d := range data {
		if d != nil {
			hook := d.(map[string]interface{})

			rolesString := expandStringSlice(hook["roles"])
			roles := make([]kops.InstanceGroupRole, len(rolesString))

			for i, role := range rolesString {
				roles[i] = kops.InstanceGroupRole(role)
			}
			spec := kops.HookSpec{
				Name:          hook["name"].(string),
				Manifest:      hook["manifest"].(string),
				Before:        expandStringSlice(hook["before"]),
				Requires:      expandStringSlice(hook["requires"]),
				Roles:         roles,
				ExecContainer: expandExecContainerAction(hook["exec_container"].([]interface{})),
			}
			if hook["disabled"].(string) != "" {
				spec.Disabled = *expandBool(hook["disabled"])
			}

			hooks = append(hooks, spec)
		}
	}

	return hooks
}

func expandIAMProfileSpec(data []interface{}) *kops.IAMProfileSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		spec := &kops.IAMProfileSpec{
			Profile: expandString(d["profile"]),
		}
		return spec
	}
	return nil
}

func expandIAMSpec(data []interface{}) *kops.IAMSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		spec := &kops.IAMSpec{}
		if d["allow_container_registry"].(string) != "" {
			spec.AllowContainerRegistry = *expandBool(d["allow_container_registry"])
		}
		if d["legacy"].(string) != "" {
			spec.Legacy = *expandBool(d["legacy"])
		}
		return spec
	}
	return nil
}

func expandInstanceGroup(d *schema.ResourceData) []*kops.InstanceGroup {
	var instanceGroups []*kops.InstanceGroup

	if ig, ok := d.GetOk("instancegroup"); ok {
		for _, e := range ig.([]interface{}) {
			m := e.(map[string]interface{})

			instanceGroup := &kops.InstanceGroup{
				ObjectMeta: expandObjectMeta(m["name"].(string), m["creation_timestamp"].(string)),
				Spec: kops.InstanceGroupSpec{
					Role:                     kops.InstanceGroupRole(m["role"].(string)),
					MachineType:              m["machine_type"].(string),
					Image:                    m["image"].(string),
					Subnets:                  expandStringSlice(m["subnets"]),
					Zones:                    expandStringSlice(m["zones"]),
					AdditionalSecurityGroups: expandStringSlice(m["additional_security_groups"]),
					AdditionalUserData:       expandUserData(m["additional_user_data"].([]interface{})),
					ExternalLoadBalancers:    expandLoadBalancer(m["external_load_balancer"].([]interface{})),
					FileAssets:               expandFileAssetSpec(m["file_asset"].([]interface{})),
					Hooks:                    expandHookSpec(m["hook"].([]interface{})),
					Kubelet:                  expandKubeletConfigSpec(m["kubelet"].([]interface{})),
				},
			}
			if m["associate_public_ip"].(string) != "" {
				instanceGroup.Spec.AssociatePublicIP = expandBool(m["associate_public_ip"])
			}
			if m["detailed_instance_monitoring"].(string) != "" {
				instanceGroup.Spec.DetailedInstanceMonitoring = expandBool(m["detailed_instance_monitoring"])
			}
			if iam, ok := m["iam"]; ok {
				instanceGroup.Spec.IAM = expandIAMProfileSpec(iam.([]interface{}))
			}
			if m["root_volume_iops"].(string) != "" {
				instanceGroup.Spec.RootVolumeIops = expandInt32(m["root_volume_iops"].(string))
			}
			if m["root_volume_size"].(string) != "" {
				instanceGroup.Spec.RootVolumeSize = expandInt32(m["root_volume_size"].(string))
			}
			rootVolumeType := m["root_volume_type"].(string)
			if rootVolumeType != "" {
				instanceGroup.Spec.RootVolumeType = &rootVolumeType
			}
			if m["root_volume_optimization"].(string) != "" {
				instanceGroup.Spec.RootVolumeOptimization = expandBool(m["root_volume_optimization"])
			}
			maxPrice := m["max_price"].(string)
			if maxPrice != "" {
				instanceGroup.Spec.MaxPrice = &maxPrice
			}
			if m["min_size"].(string) != "" {
				instanceGroup.Spec.MinSize = expandInt32(m["min_size"].(string))
			}
			if m["max_size"].(string) != "" {
				instanceGroup.Spec.MaxSize = expandInt32(m["max_size"].(string))
			}
			if cl, ok := m["cloud_labels"]; ok {
				instanceGroup.Spec.CloudLabels = expandStringMap(cl)
			}
			if nl, ok := m["node_labels"]; ok {
				instanceGroup.Spec.NodeLabels = expandStringMap(nl)
			}
			if t, ok := m["taints"]; ok {
				instanceGroup.Spec.Taints = expandStringSlice(t)
			}
			instanceGroups = append(instanceGroups, instanceGroup)
		}
	}

	s, _ := json.Marshal(instanceGroups)
	log.Printf("[DEBUG] InstanceGroups: %s", string(s))

	return instanceGroups
}

func expandKubeAPIServerConfig(data []interface{}) *kops.KubeAPIServerConfig {
	if len(data) > 0 {
		conv := data[0].(map[string]interface{})
		config := &kops.KubeAPIServerConfig{
			Address:                          conv["address"].(string),
			AuditPolicyFile:                  conv["audit_policy_file"].(string),
			BasicAuthFile:                    conv["basic_auth_file"].(string),
			BindAddress:                      conv["bind_address"].(string),
			ClientCAFile:                     conv["client_ca_file"].(string),
			CloudProvider:                    conv["cloud_provider"].(string),
			DisableAdmissionPlugins:          expandStringSlice(conv["disable_admission_plugins"]),
			EnableAdmissionPlugins:           expandStringSlice(conv["enable_admission_plugins"]),
			EtcdCAFile:                       conv["etcd_ca_file"].(string),
			EtcdCertFile:                     conv["etcd_cert_file"].(string),
			EtcdKeyFile:                      conv["etcd_key_file"].(string),
			EtcdServers:                      expandStringSlice(conv["etcd_servers"]),
			EtcdServersOverrides:             expandStringSlice(conv["etcd_servers_overrides"]),
			FeatureGates:                     expandStringMap(conv["feature_gates"]),
			InsecureBindAddress:              conv["insecure_bind_address"].(string),
			Image:                            conv["image"].(string),
			KubeletClientCertificate:         conv["kubelet_client_certificate"].(string),
			KubeletClientKey:                 conv["kubelet_client_key"].(string),
			KubeletPreferredAddressTypes:     expandStringSlice(conv["kubelet_preferred_address_types"]),
			RequestheaderAllowedNames:        expandStringSlice(conv["requestheader_allowed_names"]),
			RequestheaderClientCAFile:        conv["requestheader_client_ca_file"].(string),
			RequestheaderExtraHeaderPrefixes: expandStringSlice(conv["requestheader_extra_header_prefixes"]),
			RequestheaderGroupHeaders:        expandStringSlice(conv["requestheader_group_headers"]),
			RequestheaderUsernameHeaders:     expandStringSlice(conv["requestheader_username_headers"]),
			RuntimeConfig:                    expandStringMap(conv["runtime_config"]),
			ServiceClusterIPRange:            conv["service_cluster_ip_range"].(string),
			ServiceNodePortRange:             conv["service_node_port_range"].(string),
			TLSCertFile:                      conv["tls_cert_file"].(string),
			TLSPrivateKeyFile:                conv["tls_private_key_file"].(string),
			TokenAuthFile:                    conv["token_auth_file"].(string),
		}
		if conv["insecure_port"].(string) != "" {
			config.InsecurePort = *expandInt32(conv["insecure_port"])
		}
		if conv["log_level"].(string) != "" {
			config.LogLevel = *expandInt32(conv["log_level"])
		}
		if conv["max_requests_inflight"].(string) != "" {
			config.MaxRequestsInflight = *expandInt32(conv["max_requests_inflight"])
		}
		if conv["secure_port"].(string) != "" {
			config.SecurePort = *expandInt32(conv["secure_port"])
		}
		if conv["api_server_count"].(string) != "" {
			config.APIServerCount = expandInt32(conv["api_server_count"].(string))
		}
		auditLogFormat := conv["audit_log_format"].(string)
		if auditLogFormat != "" {
			config.AuditLogFormat = &auditLogFormat
		}
		if conv["audit_log_max_age"].(string) != "" {
			config.AuditLogMaxAge = expandInt32(conv["audit_log_max_age"].(string))
		}
		if conv["audit_log_max_backups"].(string) != "" {
			config.AuditLogMaxBackups = expandInt32(conv["audit_log_max_backups"].(string))
		}
		if conv["audit_log_max_size"].(string) != "" {
			config.AuditLogMaxSize = expandInt32(conv["audit_log_max_size"].(string))
		}
		auditLogPath := conv["audit_log_path"].(string)
		if auditLogPath != "" {
			config.AuditLogPath = &auditLogPath
		}
		if conv["authentication_token_webhook_cache_ttl"].(string) != "" {
			config.AuthenticationTokenWebhookCacheTTL = expandDuration(conv["authentication_token_webhook_cache_ttl"])
		}
		authenticationTokenWebhookConfigFile := conv["authentication_token_webhook_config_file"].(string)
		if authenticationTokenWebhookConfigFile != "" {
			config.AuthenticationTokenWebhookConfigFile = &authenticationTokenWebhookConfigFile
		}
		authorizationMode := conv["authorization_mode"].(string)
		if authorizationMode != "" {
			config.AuthorizationMode = &authorizationMode
		}
		authorizationRBACSuperUser := conv["authorization_rbac_super_user"].(string)
		if authorizationRBACSuperUser != "" {
			config.AuthorizationRBACSuperUser = &authorizationRBACSuperUser
		}
		if conv["allow_privileged"].(string) != "" {
			config.AllowPrivileged = expandBool(conv["allow_privileged"])
		}
		if conv["anonymous_auth"].(string) != "" {
			config.AnonymousAuth = expandBool(conv["anonymous_auth"])
		}
		if conv["enable_aggregator_routing"].(string) != "" {
			config.EnableAggregatorRouting = expandBool(conv["enable_aggregator_routing"])
		}
		if conv["enable_bootstrap_auth_token"].(string) != "" {
			config.EnableBootstrapAuthToken = expandBool(conv["enable_bootstrap_auth_token"])
		}
		if conv["etcd_quorum_read"].(string) != "" {
			config.EtcdQuorumRead = expandBool(conv["etcd_quorum_read"])
		}
		experimentalEncryptionProviderConfig := conv["experimental_encryption_provider_config"].(string)
		if experimentalEncryptionProviderConfig != "" {
			config.ExperimentalEncryptionProviderConfig = &experimentalEncryptionProviderConfig
		}
		if conv["mix_request_timeout"].(string) != "" {
			config.MinRequestTimeout = expandInt32(conv["mix_request_timeout"])
		}
		oidcCAFile := conv["oidc_ca_file"].(string)
		if oidcCAFile != "" {
			config.OIDCCAFile = &oidcCAFile
		}
		oidcClientID := conv["oidc_client_id"].(string)
		if oidcClientID != "" {
			config.OIDCClientID = &oidcClientID
		}
		oidcGroupsClaim := conv["oidc_groups_claim"].(string)
		if oidcGroupsClaim != "" {
			config.OIDCGroupsClaim = &oidcGroupsClaim
		}
		oidcGroupsPrefix := conv["oidc_groups_prefix"].(string)
		if oidcGroupsPrefix != "" {
			config.OIDCGroupsPrefix = &oidcGroupsPrefix
		}
		oidcIssuerURL := conv["oidc_issuer_url"].(string)
		if oidcIssuerURL != "" {
			config.OIDCIssuerURL = &oidcIssuerURL
		}
		oidcUsernameClaim := conv["oidc_username_claim"].(string)
		if oidcUsernameClaim != "" {
			config.OIDCUsernameClaim = &oidcUsernameClaim
		}
		oidcUsernamePrefix := conv["oidc_username_prefix"].(string)
		if oidcUsernamePrefix != "" {
			config.OIDCUsernamePrefix = &oidcUsernamePrefix
		}
		proxyClientCertFile := conv["proxy_client_cert_file"].(string)
		if proxyClientCertFile != "" {
			config.ProxyClientCertFile = &proxyClientCertFile
		}
		proxyClientKeyFile := conv["proxy_client_key_file"].(string)
		if proxyClientKeyFile != "" {
			config.ProxyClientKeyFile = &proxyClientKeyFile
		}
		storageBackend := conv["storage_backend"].(string)
		if storageBackend != "" {
			config.StorageBackend = &storageBackend
		}
	}
	return nil
}

func expandKubeControllerManagerConfig(data []interface{}) *kops.KubeControllerManagerConfig {
	if len(data) > 0 {
		conv := data[0].(map[string]interface{})
		config := &kops.KubeControllerManagerConfig{
			CloudProvider:        conv["cloud_provider"].(string),
			ClusterCIDR:          conv["cluster_cidr"].(string),
			ClusterName:          conv["cluster_name"].(string),
			ConfigureCloudRoutes: expandBool(conv["configure_cloud_routes"]),
			FeatureGates:         expandStringMap(conv["feature_gates"]),
			Image:                conv["image"].(string),
			LeaderElection:       expandLeaderElectionConfiguration(conv["leader_election"].([]interface{})),
		}
		if conv["log_level"].(string) != "" {
			config.LogLevel = *expandInt32(conv["log_level"])
		}
		if conv["allocate_node_cidrs"].(string) != "" {
			config.AllocateNodeCIDRs = expandBool(conv["allocate_node_cidrs"])
		}
		if conv["attach_detach_reconcile_sync_period"].(string) != "" {
			config.AttachDetachReconcileSyncPeriod = expandDuration(conv["attach_detach_reconcile_sync_period"])
		}
		if conv["cidr_allocator_type"].(string) != "" {
			config.CIDRAllocatorType = expandString(conv["cidr_allocator_type"])
		}
		if conv["horizontal_pod_autoscaler_downscale_delay"].(string) != "" {
			config.HorizontalPodAutoscalerDownscaleDelay = expandDuration(conv["horizontal_pod_autoscaler_downscale_delay"])
		}
		if conv["horizontal_pod_autoscaler_sync_period"].(string) != "" {
			config.HorizontalPodAutoscalerSyncPeriod = expandDuration(conv["horizontal_pod_autoscaler_sync_period"])
		}
		if conv["horizontal_pod_autoscaler_upscale_delay"].(string) != "" {
			config.HorizontalPodAutoscalerUpscaleDelay = expandDuration(conv["horizontal_pod_autoscaler_upscale_delay"])
		}
		if conv["horizontal_pod_autoscaler_use_rest_clients"].(string) != "" {
			config.HorizontalPodAutoscalerUseRestClients = expandBool(conv["horizontal_pod_autoscaler_use_rest_clients"])
		}
		master := conv["master"].(string)
		if master != "" {
			config.Master = master
		}
		if conv["node_monitor_grace_period"].(string) != "" {
			config.NodeMonitorGracePeriod = expandDuration(conv["node_monitor_grace_period"])
		}
		if conv["node_monitor_period"].(string) != "" {
			config.NodeMonitorPeriod = expandDuration(conv["node_monitor_period"])
		}
		if conv["pod_eviction_timeout"].(string) != "" {
			config.PodEvictionTimeout = expandDuration(conv["pod_eviction_timeout"])
		}
		if conv["root_ca_file"].(string) != "" {
			config.RootCAFile = conv["root_ca_file"].(string)
		}
		if conv["service_account_private_key_file"].(string) != "" {
			config.ServiceAccountPrivateKeyFile = conv["service_account_private_key_file"].(string)
		}
		if conv["terminated_pod_gc_threshold"].(string) != "" {
			config.TerminatedPodGCThreshold = expandInt32(conv["terminated_pod_gc_threshold"])
		}
		if conv["use_service_account_credentials"].(string) != "" {
			config.UseServiceAccountCredentials = expandBool(conv["use_service_account_credentials"])
		}
		return config
	}
	return nil
}

func expandKubeDNSConfig(data []interface{}) *kops.KubeDNSConfig {
	if len(data) > 0 {
		conv := data[0].(map[string]interface{})
		config := &kops.KubeDNSConfig{

			Domain:              conv["domain"].(string),
			Image:               conv["image"].(string),
			Provider:            conv["provider"].(string),
			ServerIP:            conv["server_ip"].(string),
			StubDomains:         expandStringStringSliceMap(conv["stub_domains"]),
			UpstreamNameservers: expandStringSlice(conv["upstream_nameservers"]),
		}
		if conv["cache_max_concurrent"].(string) != "" {
			config.CacheMaxConcurrent = *expandInt(conv["cache_max_concurrent"])
		}
		if conv["cache_max_size"].(string) != "" {
			config.CacheMaxSize = *expandInt(conv["cache_max_size"])
		}
		if conv["replicas"].(string) != "" {
			config.Replicas = *expandInt(conv["replicas"])
		}
		return config
	}
	return nil
}

func expandKubeletConfigSpec(data []interface{}) *kops.KubeletConfigSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})

		config := &kops.KubeletConfigSpec{
			APIServers:                       d["api_servers"].(string),
			AuthorizationMode:                d["authorization_mode"].(string),
			BootstrapKubeconfig:              d["bootstrap_kubeconfig"].(string),
			CgroupRoot:                       d["cgroup_root"].(string),
			ClientCAFile:                     d["client_ca_file"].(string),
			CloudProvider:                    d["cloud_provider"].(string),
			ClusterDNS:                       d["cluster_dns"].(string),
			ClusterDomain:                    d["cluster_domain"].(string),
			EnforceNodeAllocatable:           d["enforce_node_allocatable"].(string),
			EvictionMinimumReclaim:           d["eviction_minimum_reclaim"].(string),
			EvictionSoft:                     d["eviction_soft"].(string),
			EvictionSoftGracePeriod:          d["eviction_soft_grace_period"].(string),
			ExperimentalAllowedUnsafeSysctls: expandStringSlice(d["experimental_allowed_unsafe_sysctls"]),
			FeatureGates:                     expandStringMap(d["feature_gates"]),
			HairpinMode:                      d["hairpin_mode"].(string),
			HostnameOverride:                 d["hostname_override"].(string),
			KubeconfigPath:                   d["kubeconfig_path"].(string),
			KubeletCgroups:                   d["kubelet_cgroups"].(string),
			KubeReserved:                     expandStringMap(d["kube_reserved"]),
			KubeReservedCgroup:               d["kube_reserved_cgroup"].(string),
			NetworkPluginName:                d["network_plugin_name"].(string),
			NodeLabels:                       expandStringMap(d["node_labels"]),
			NonMasqueradeCIDR:                d["non_masquerade_cidr"].(string),
			NvidiaGPUs:                       *expandInt32(d["nvidia_gpus"]),
			PodCIDR:                          d["pod_cidr"].(string),
			PodInfraContainerImage:           d["pod_infra_container_image"].(string),
			PodManifestPath:                  d["pod_manifest_path"].(string),
			RootDir:                          d["root_dir"].(string),
			RuntimeCgroups:                   d["runtime_cgroups"].(string),
			SystemCgroups:                    d["system_cgroups"].(string),
			SystemReserved:                   expandStringMap(d["system_reserved"]),
			SystemReservedCgroup:             d["system_reserved_cgroup"].(string),
			Taints:                           expandStringSlice(d["taints"]),
			TLSCertFile:                      d["tls_cert_file"].(string),
			TLSPrivateKeyFile:                d["tls_private_key_file"].(string),
			VolumePluginDirectory:            d["volume_plugin_directory"].(string),
		}
		if d["allow_privileged"].(string) != "" {
			config.AllowPrivileged = expandBool(d["allow_privileged"])
		}
		if d["anonymous_auth"].(string) != "" {
			config.AnonymousAuth = expandBool(d["anonymous_auth"])
		}
		if d["authentication_token_webhook"].(string) != "" {
			config.AuthenticationTokenWebhook = expandBool(d["authentication_token_webhook"])
		}
		if d["authentication_token_webhook_cache_ttl"].(string) != "" {
			config.AuthenticationTokenWebhookCacheTTL = expandDuration(d["authentication_token_webhook_cache_ttl"])
		}
		// if d["babysit_daemons"].(string) != "" {
		// 	config.BabysitDaemons = expandBool(d["babysit_daemons"])
		// }
		if d["configure_cbr0"].(string) != "" {
			config.ConfigureCBR0 = expandBool(d["configure_cbr0"])
		}
		if d["docker_disable_shared_pid"].(string) != "" {
			config.DockerDisableSharedPID = expandBool(d["docker_disable_shared_pid"])
		}
		if d["enable_custom_metrics"].(string) != "" {
			config.EnableCustomMetrics = expandBool(d["enable_custom_metrics"])
		}
		if d["enable_debugging_handlers"].(string) != "" {
			config.EnableDebuggingHandlers = expandBool(d["enable_debugging_handlers"])
		}
		evictionHard := d["eviction_hard"].(string)
		if evictionHard != "" {
			config.EvictionHard = &evictionHard
		}
		if d["eviction_max_pod_grace_period"].(string) != "" {
			config.EvictionMaxPodGracePeriod = *expandInt32(d["eviction_max_pod_grace_period"])
		}
		if d["eviction_pressure_transition_period"].(string) != "" {
			config.EvictionPressureTransitionPeriod = expandDuration(d["eviction_pressure_transition_period"])
		}
		if d["fail_swap_on"].(string) != "" {
			config.FailSwapOn = expandBool(d["fail_swap_on"])

		}
		if d["image_gc_high_threshold_percent"].(string) != "" {
			config.ImageGCHighThresholdPercent = expandInt32(d["image_gc_high_threshold_percent"])
		}
		if d["image_gc_low_threshold_percent"].(string) != "" {
			config.ImageGCLowThresholdPercent = expandInt32(d["image_gc_low_threshold_percent"])
		}
		if d["image_pull_progress_deadline"].(string) != "" {
			config.ImagePullProgressDeadline = expandDuration(d["image_pull_progress_deadline"])
		}
		if d["log_level"].(string) != "" {
			config.LogLevel = expandInt32(d["log_level"])
		}
		if d["max_pods"].(string) != "" {
			config.MaxPods = expandInt32(d["max_pods"])
		}
		if d["network_plugin_mtu"].(string) != "" {
			config.NetworkPluginMTU = expandInt32(d["network_plugin_mtu"])
		}
		if d["node_status_update_frequency"].(string) != "" {
			config.NodeStatusUpdateFrequency = expandDuration(d["node_status_update_frequency"])
		}
		if d["read_only_port"].(string) != "" {
			config.ReadOnlyPort = expandInt32(d["read_only_port"])
		}
		if d["reconcile_cidr"].(string) != "" {
			config.ReconcileCIDR = expandBool(d["reconcile_cidr"])
		}
		if d["register_node"].(string) != "" {
			config.RegisterNode = expandBool(d["register_node"])
		}
		if d["register_schedulable"].(string) != "" {
			config.RegisterSchedulable = expandBool(d["register_schedulable"])
		}
		// if d["require_kubeconfig"].(string) != "" {
		// 	config.RequireKubeconfig = expandBool(d["require_kubeconfig"])
		// }
		resolverConfig := d["resolver_config"].(string)
		if resolverConfig != "" {
			config.ResolverConfig = &resolverConfig
		}
		if d["runtime_request_timeout"].(string) != "" {
			config.RuntimeRequestTimeout = expandDuration(d["runtime_request_timeout"])
		}
		seccompProfileRoot := d["seccomp_profile_root"].(string)
		if seccompProfileRoot != "" {
			config.SeccompProfileRoot = &seccompProfileRoot
		}
		if d["serialize_image_pulls"].(string) != "" {
			config.SerializeImagePulls = expandBool(d["serialize_image_pulls"])
		}
		if d["streaming_connection_idle_timeout"].(string) != "" {
			config.StreamingConnectionIdleTimeout = expandDuration(d["streaming_connection_idle_timeout"])
		}
		if d["volume_stats_agg_period"].(string) != "" {
			config.VolumeStatsAggPeriod = expandDuration(d["volume_stats_agg_period"])
		}
		return config
	}
	return nil
}

func expandKubeProxyConfig(data []interface{}) *kops.KubeProxyConfig {
	if len(data) > 0 {
		conv := data[0].(map[string]interface{})
		config := &kops.KubeProxyConfig{
			BindAddress:      conv["bind_address"].(string),
			ClusterCIDR:      conv["cluster_cidr"].(string),
			CPULimit:         conv["cpu_limit"].(string),
			CPURequest:       conv["cpu_request"].(string),
			FeatureGates:     expandStringMap(conv["feature_gates"]),
			HostnameOverride: conv["hostname_override"].(string),
			Image:            conv["image"].(string),
			Master:           conv["master"].(string),
			MemoryLimit:      conv["memory_limit"].(string),
			MemoryRequest:    conv["memory_request"].(string),
			ProxyMode:        conv["proxy_mode"].(string),
		}
		if conv["log_level"].(string) != "" {
			config.LogLevel = *expandInt32(conv["log_level"])
		}
		if conv["conntrack_max_per_core"].(string) != "" {
			config.ConntrackMaxPerCore = expandInt32(conv["conntrack_max_per_core"])
		}
		if conv["conntrack_min"].(string) != "" {
			config.ConntrackMin = expandInt32(conv["conntrack_min"])
		}
		enabled := conv["enabled"].(string)
		if enabled != "" {
			config.Enabled = expandBool(conv["enabled"])
		}
		return config
	}
	return nil
}

func expandKubeSchedulerConfig(data []interface{}) *kops.KubeSchedulerConfig {
	if len(data) > 0 {
		conv := data[0].(map[string]interface{})
		config := &kops.KubeSchedulerConfig{
			FeatureGates:   expandStringMap(conv["feature_gates"]),
			Image:          conv["image"].(string),
			LeaderElection: expandLeaderElectionConfiguration(conv["leader_election"].([]interface{})),
			Master:         conv["master"].(string),
		}
		if conv["log_level"].(string) != "" {
			config.LogLevel = *expandInt32(conv["log_level"])
		}
		if conv["use_policy_config_map"].(string) != "" {
			config.UsePolicyConfigMap = expandBool(conv["use_policy_config_map"])
		}
		return config
	}
	return nil
}

func expandLeaderElectionConfiguration(data []interface{}) *kops.LeaderElectionConfiguration {
	if len(data) > 0 {
		conv := data[0].(map[string]interface{})
		config := &kops.LeaderElectionConfiguration{}
		leaderElect := conv["leader_elect"].(string)
		if leaderElect != "" {
			config.LeaderElect = expandBool(conv["leader_elect"])
		}
		return config
	}
	return nil
}

func expandLoadBalancer(data []interface{}) []kops.LoadBalancer {
	var loadBalancers []kops.LoadBalancer

	for _, d := range data {
		if d != nil {
			lb := d.(map[string]interface{})
			name := lb["load_balancer_name"].(string)
			target := lb["target_group_arn"].(string)

			loadBalancers = append(loadBalancers, kops.LoadBalancer{
				LoadBalancerName: &name,
				TargetGroupARN:   &target,
			})
		}
	}

	return loadBalancers
}

func expandLoadBalancerAccessSpec(data []interface{}) *kops.LoadBalancerAccessSpec {
	if len(data) > 0 {
		d := data[0].(map[string]interface{})
		loadBalancerAccessSpec := &kops.LoadBalancerAccessSpec{
			Type: kops.LoadBalancerType(d["type"].(string)),
		}
		if d["idle_timeout_seconds"].(string) != "" {
			loadBalancerAccessSpec.IdleTimeoutSeconds = expandInt64(d["idle_timeout_seconds"])
		}
		if len(d["additional_security_groups"].([]interface{})) > 0 {
			loadBalancerAccessSpec.AdditionalSecurityGroups = expandStringSlice(d["additional_security_groups"])
		}
		if d["use_for_internal_api"].(string) != "" {
			loadBalancerAccessSpec.UseForInternalApi = *expandBool(d["use_for_internal_api"])
		}
		if d["ssl_certificate"].(string) != "" {
			loadBalancerAccessSpec.SSLCertificate = d["ssl_certificate"].(string)
		}
		return loadBalancerAccessSpec
	}
	return nil
}

func expandNetworkingSpec(data []interface{}) *kops.NetworkingSpec {
	spec := data[0].(map[string]interface{})

	switch spec["name"] {
	case "classic":
		return &kops.NetworkingSpec{
			Classic: &kops.ClassicNetworkingSpec{},
		}
	case "kubenet":
		return &kops.NetworkingSpec{
			Kubenet: &kops.KubenetNetworkingSpec{},
		}
	case "external":
		return &kops.NetworkingSpec{
			External: &kops.ExternalNetworkingSpec{},
		}
	case "cni":
		return &kops.NetworkingSpec{
			CNI: &kops.CNINetworkingSpec{},
		}
	case "kopeio":
		return &kops.NetworkingSpec{
			Kopeio: &kops.KopeioNetworkingSpec{},
		}
	case "weave":
		return &kops.NetworkingSpec{
			Weave: &kops.WeaveNetworkingSpec{},
		}
	case "flannel":
		return &kops.NetworkingSpec{
			Flannel: &kops.FlannelNetworkingSpec{},
		}
	case "calico":
		return &kops.NetworkingSpec{
			Calico: &kops.CalicoNetworkingSpec{},
		}
	case "canal":
		return &kops.NetworkingSpec{
			Canal: &kops.CanalNetworkingSpec{},
		}
	case "kuberouter":
		return &kops.NetworkingSpec{
			Kuberouter: &kops.KuberouterNetworkingSpec{},
		}
	case "romana":
		return &kops.NetworkingSpec{
			Romana: &kops.RomanaNetworkingSpec{},
		}
	case "amazonvpc":
		return &kops.NetworkingSpec{
			AmazonVPC: &kops.AmazonVPCNetworkingSpec{},
		}
	case "cilium":
		return &kops.NetworkingSpec{
			Cilium: &kops.CiliumNetworkingSpec{},
		}
	default:
	}
	return &kops.NetworkingSpec{}
}

func expandObjectMeta(name string, creationTimestamp string) v1.ObjectMeta {
	meta := v1.ObjectMeta{
		Name: name,
	}
	timestamp, _ := time.Parse("2006-01-02 15:04:05.999999999 -0700 MST", creationTimestamp)
	meta.CreationTimestamp = v1.Time{Time: timestamp}

	s, _ := json.Marshal(meta)
	log.Printf("[DEBUG] Metadata: %s", string(s))

	return meta
}

func expandTopologySpec(data []interface{}) *kops.TopologySpec {
	if len(data) > 0 {
		topology := &kops.TopologySpec{}
		conv := data[0].(map[string]interface{})
		topology.Masters = conv["masters"].(string)
		topology.Nodes = conv["nodes"].(string)
		topology.Bastion = expandBastionSpec(conv["bastion"].([]interface{}))
		topology.DNS = expandDNSSpec(conv["dns"].([]interface{}))
		return topology
	}
	return nil
}

func expandUserData(data []interface{}) []kops.UserData {
	var userData []kops.UserData

	for _, d := range data {
		if d != nil {
			ud := d.(map[string]interface{})
			userData = append(userData, kops.UserData{
				Name:    ud["name"].(string),
				Type:    ud["type"].(string),
				Content: ud["content"].(string),
			})
		}
	}

	return userData
}

func expandBool(data interface{}) *bool {
	if data != nil {
		parsed, _ := strconv.ParseBool(data.(string))
		return &parsed
	}
	return nil
}

func expandDuration(data interface{}) *v1.Duration {
	if data != nil {
		parsed, _ := time.ParseDuration(data.(string))
		return &v1.Duration{Duration: parsed}
	}
	return nil
}

func expandInt(data interface{}) *int {
	if data != nil {
		parsed, _ := strconv.Atoi(data.(string))
		return &parsed
	}
	return nil
}

func expandInt32(data interface{}) *int32 {
	if data != nil {
		parsed, _ := strconv.Atoi(data.(string))
		i := int32(parsed)
		return &i
	}
	return nil
}

func expandInt64(data interface{}) *int64 {
	if data != nil {
		parsed, _ := strconv.ParseInt(data.(string), 10, 64)
		return &parsed
	}
	return nil
}

func expandString(data interface{}) *string {
	if data != nil {
		parsed := data.(string)
		return &parsed
	}
	return nil
}

func expandStringMap(data interface{}) map[string]string {
	ret := make(map[string]string)
	if data != nil {
		d := data.(map[string]interface{})
		for key, val := range d {
			ret[key] = val.(string)
		}
	}
	return ret
}

func expandStringSlice(data interface{}) []string {
	var ret []string
	if data != nil {
		d := data.([]interface{})
		for _, val := range d {
			ret = append(ret, val.(string))
		}
	}
	return ret
}

func expandStringStringSliceMap(data interface{}) map[string][]string {
	ret := make(map[string][]string)
	if data != nil {
		d := data.(map[string]interface{})
		for key, val := range d {
			ret[key] = strings.Split(val.(string), ",")
		}
	}
	return ret
}

func stringToAuthorizationSpec(s string) *kops.AuthorizationSpec {
	authorization := &kops.AuthorizationSpec{}
	switch s {
	case "AlwaysAllow":
		authorization.AlwaysAllow = &kops.AlwaysAllowAuthorizationSpec{}
	case "RBAC":
		authorization.RBAC = &kops.RBACAuthorizationSpec{}
	}
	return authorization
}
