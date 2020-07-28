package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaKubeletConfigSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: false,
		MaxItems: 1,
		Elem:     resourceKubeletConfigSpec(),
	}
}

func schemaKubeletConfigSpecComputed() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem:     resourceKubeletConfigSpec(),
	}
}

func resourceKubeletConfigSpec() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"api_servers":                            schemaStringOptionalComputed(),
			"authorization_mode":                     schemaStringOptionalComputed(),
			"allow_privileged":                       schemaBoolOptional(),
			"anonymous_auth":                         schemaBoolOptional(),
			"authentication_token_webhook":           schemaBoolOptional(),
			"authentication_token_webhook_cache_ttl": schemaStringOptionalComputed(),
			// "babysit_daemons":                        schemaBoolOptional(),
			"bootstrap_kubeconfig":                schemaStringOptionalComputed(),
			"cgroup_root":                         schemaStringOptionalComputed(),
			"client_ca_file":                      schemaStringOptionalComputed(),
			"cloud_provider":                      schemaStringOptionalComputed(),
			"cluster_dns":                         schemaStringOptionalComputed(),
			"cluster_domain":                      schemaStringOptionalComputed(),
			"configure_cbr0":                      schemaBoolOptional(),
			"docker_disable_shared_pid":           schemaBoolOptional(),
			"enable_custom_metrics":               schemaBoolOptional(),
			"enable_debugging_handlers":           schemaBoolOptional(),
			"enforce_node_allocatable":            schemaStringOptionalComputed(),
			"eviction_hard":                       schemaStringOptionalComputed(),
			"eviction_max_pod_grace_period":       schemaIntOptional(),
			"eviction_minimum_reclaim":            schemaStringOptionalComputed(),
			"eviction_pressure_transition_period": schemaStringOptionalComputed(),
			"eviction_soft":                       schemaStringOptionalComputed(),
			"eviction_soft_grace_period":          schemaStringOptionalComputed(),
			"experimental_allowed_unsafe_sysctls": schemaStringSliceOptional(),
			"fail_swap_on":                        schemaBoolOptional(),
			"feature_gates":                       schemaStringMap(),
			"hairpin_mode":                        schemaStringOptionalComputed(),
			"hostname_override":                   schemaStringOptionalComputed(),
			"image_gc_high_threshold_percent":     schemaIntOptional(),
			"image_gc_low_threshold_percent":      schemaIntOptional(),
			"image_pull_progress_deadline":        schemaStringOptionalComputed(),
			"kubeconfig_path":                     schemaStringOptionalComputed(),
			"kubelet_cgroups":                     schemaStringOptionalComputed(),
			"kube_reserved":                       schemaStringMap(),
			"kube_reserved_cgroup":                schemaStringOptionalComputed(),
			"log_level":                           schemaIntOptional(),
			"max_pods":                            schemaIntOptional(),
			"network_plugin_mtu":                  schemaIntOptional(),
			"network_plugin_name":                 schemaStringOptionalComputed(),
			"node_labels":                         schemaStringMap(),
			"node_status_update_frequency":        schemaStringOptionalComputed(),
			"non_masquerade_cidr":                 schemaStringOptionalComputed(),
			"nvidia_gpus":                         schemaIntOptional(),
			"pod_cidr":                            schemaStringOptionalComputed(),
			"pod_infra_container_image":           schemaStringOptionalComputed(),
			"pod_manifest_path":                   schemaStringOptionalComputed(),
			"read_only_port":                      schemaIntOptional(),
			"reconcile_cidr":                      schemaBoolOptional(),
			"register_node":                       schemaBoolOptional(),
			"register_schedulable":                schemaBoolOptional(),
			// "require_kubeconfig":                     schemaBoolOptional(),
			"resolver_config":                   schemaStringOptionalComputed(),
			"root_dir":                          schemaStringOptionalComputed(),
			"runtime_request_timeout":           schemaStringOptionalComputed(),
			"runtime_cgroups":                   schemaStringOptionalComputed(),
			"seccomp_profile_root":              schemaStringOptionalComputed(),
			"serialize_image_pulls":             schemaBoolOptional(),
			"streaming_connection_idle_timeout": schemaStringOptionalComputed(),
			"system_cgroups":                    schemaStringOptionalComputed(),
			"system_reserved":                   schemaStringMap(),
			"system_reserved_cgroup":            schemaStringOptionalComputed(),
			"taints":                            schemaStringSliceOptional(),
			"tls_cert_file":                     schemaStringOptionalComputed(),
			"tls_private_key_file":              schemaStringOptionalComputed(),
			"volume_plugin_directory":           schemaStringOptionalComputed(),
			"volume_stats_agg_period":           schemaStringOptionalComputed(),
		},
	}
}
