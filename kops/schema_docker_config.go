package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaDockerConfig() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"authorization_plugins": schemaStringSliceOptional(),
				"bridge":                schemaStringOptional(),
				"bridge_ip":             schemaStringOptional(),
				"data_root":             schemaStringOptional(),
				"default_ulimit":        schemaStringSliceOptional(),
				"exec_root":             schemaStringOptional(),
				"hosts":                 schemaStringSliceOptional(),
				"ip_masq":               schemaBoolOptionalComputed(),
				"ip_tables":             schemaBoolOptionalComputed(),
				"insecure_registry":     schemaStringOptional(),
				"live_restore":          schemaBoolOptional(),
				"log_driver":            schemaStringOptionalComputed(),
				"log_level":             schemaStringOptionalComputed(),
				"log_opt":               schemaStringSliceOptionalComputed(),
				"mtu":                   schemaIntOptional(),
				"registry_mirrors":      schemaStringSliceOptional(),
				"storage":               schemaStringOptionalComputed(),
				"storage_opts":          schemaStringSliceOptional(),
				"user_namespace_remap":  schemaStringOptional(),
				"version":               schemaStringOptionalComputed(),
			},
		},
	}
}
