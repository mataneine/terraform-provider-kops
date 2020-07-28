package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaKubeDNSConfig() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"cache_max_concurrent": schemaIntOptional(),
				"cache_max_size":       schemaIntOptional(),
				"domain":               schemaStringOptionalComputed(),
				"image":                schemaStringOptionalComputed(),
				"provider":             schemaStringOptionalComputed(),
				"replicas":             schemaIntOptional(),
				"server_ip":            schemaStringOptionalComputed(),
				"stub_domains":         schemaStringMap(),
				"upstream_nameservers": schemaStringSliceOptional(),
			},
		},
	}
}
