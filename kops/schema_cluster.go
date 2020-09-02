package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaCluster() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"additional_policies":     schemaStringMap(),
		"api":                     schemaAccessSpec(),
		"authorization":           schemaStringInSliceOptionalDefault([]string{"AlwaysAllow", "RBAC"}, "AlwaysAllow"),
		"channel":                 schemaStringOptionalComputed(),
		"cloud_labels":            schemaStringMap(),
		"cloud_provider":          schemaStringRequired(),
		"cluster_dnsdomain":       schemaStringOptionalComputed(),
		"config_base":             schemaStringComputed(),
		"config_store":            schemaStringOptionalComputed(),
		"creation_timestamp":      schemaStringComputed(),
		"dns_zone":                schemaStringOptionalComputed(),
		"docker":                  schemaDockerConfig(),
		"etcd_cluster":            schemaEtcdClusterSpec(),
		"iam":                     schemaIAMSpec(),
		"instancegroup":           schemaInstanceGroup(),
		"key_store":               schemaStringOptionalComputed(),
		"kube_api_server":         schemaKubeAPIServerConfig(),
		"kube_controller_manager": schemaKubeControllerManagerConfig(),
		"kube_dns":                schemaKubeDNSConfig(),
		"kube_proxy":              schemaKubeProxyConfig(),
		"kube_scheduler":          schemaKubeSchedulerConfig(),
		"kubelet":                 schemaKubeletConfigSpecComputed(),
		"kubernetes_api_access":   schemaStringSliceOptional(),
		"kubernetes_version":      schemaStringRequired(),
		"master_internal_name":    schemaStringOptionalComputed(),
		"master_kubelet":          schemaKubeletConfigSpecComputed(),
		"master_public_name":      schemaStringOptionalComputed(),
		"name":                    schemaStringRequired(),
		"network_cidr":            schemaCIDRStringOptional(),
		"network_id":              schemaStringOptional(),
		"networking":              schemaNetworkingSpec(),
		"non_masquerade_cidr":     schemaCIDRStringOptional(),
		"project":                 schemaStringOptional(),
		"secret_store":            schemaStringOptionalComputed(),
		"service_cluster_iprange": schemaStringOptionalComputed(),
		"ssh_access":              schemaStringSliceOptional(),
		"sshkey_name":             schemaStringOptional(),
		"sshkey_path":             schemaStringOptionalComputed(),
		"subnet":                  schemaClusterSubnetSpec(),
		"topology":                schemaTopologySpec(),
	}
}
