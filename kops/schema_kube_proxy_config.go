package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaKubeProxyConfig() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"bind_address":           schemaStringOptionalComputed(),
				"conntrack_max_per_core": schemaIntOptional(),
				"conntrack_min":          schemaIntOptional(),
				"cluster_cidr":           schemaStringOptionalComputed(),
				"cpu_limit":              schemaStringOptionalComputed(),
				"cpu_request":            schemaStringOptionalComputed(),
				"enabled":                schemaBoolOptional(),
				"feature_gates":          schemaStringMap(),
				"hostname_override":      schemaStringOptionalComputed(),
				"image":                  schemaStringOptionalComputed(),
				"log_level":              schemaIntOptional(),
				"master":                 schemaStringOptionalComputed(),
				"memory_limit":           schemaStringOptionalComputed(),
				"memory_request":         schemaStringOptionalComputed(),
				"proxy_mode":             schemaStringOptionalComputed(),
			},
		},
	}
}
