package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaKubeControllerManagerConfig() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"allocate_node_cidrs":                        schemaBoolOptionalComputed(),
				"attach_detach_reconcile_sync_period":        schemaStringOptionalComputed(),
				"cidr_allocator_type":                        schemaStringOptional(),
				"cloud_provider":                             schemaStringOptionalComputed(),
				"cluster_cidr":                               schemaStringOptionalComputed(),
				"cluster_name":                               schemaStringOptionalComputed(),
				"configure_cloud_routes":                     schemaBoolOptionalComputed(),
				"feature_gates":                              schemaStringMap(),
				"horizontal_pod_autoscaler_downscale_delay":  schemaStringOptional(),
				"horizontal_pod_autoscaler_sync_period":      schemaStringOptional(),
				"horizontal_pod_autoscaler_upscale_delay":    schemaStringOptional(),
				"horizontal_pod_autoscaler_use_rest_clients": schemaBoolOptional(),
				"image":                            schemaStringOptionalComputed(),
				"leader_election":                  schemaLeaderElectionConfiguration(),
				"log_level":                        schemaIntOptionalComputed(),
				"master":                           schemaStringOptional(),
				"node_monitor_grace_period":        schemaStringOptional(),
				"node_monitor_period":              schemaStringOptional(),
				"pod_eviction_timeout":             schemaStringOptional(),
				"root_ca_file":                     schemaStringOptional(),
				"service_account_private_key_file": schemaStringOptional(),
				"terminated_pod_gc_threshold":      schemaIntOptional(),
				"use_service_account_credentials":  schemaBoolOptionalComputed(),
			},
		},
	}
}
