package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaKubeSchedulerConfig() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"feature_gates":         schemaStringMap(),
				"image":                 schemaStringOptionalComputed(),
				"leader_election":       schemaLeaderElectionConfiguration(),
				"log_level":             schemaIntOptional(),
				"master":                schemaStringOptionalComputed(),
				"use_policy_config_map": schemaBoolOptional(),
			},
		},
	}
}
