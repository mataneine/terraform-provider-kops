package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaLoadBalancerAccessSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"type":                       schemaStringInSliceOptionalDefault([]string{"Public", "Internal"}, "Public"),
				"idle_timeout_seconds":       schemaIntOptional(),
				"additional_security_groups": schemaStringSliceOptional(),
				"use_for_internal_api":       schemaBoolOptionalComputed(),
				"ssl_certificate":            schemaStringOptional(),
			},
		},
	}
}
