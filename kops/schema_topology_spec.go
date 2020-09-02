package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaTopologySpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"masters": schemaStringOptionalDefault("public"),
				"nodes":   schemaStringOptionalDefault("public"),
				"bastion": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"bastion_public_name":  schemaStringOptional(),
							"idle_timeout_seconds": schemaIntOptional(),
						},
					},
				},
				"dns": {
					Type:     schema.TypeList,
					Required: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"type": schemaStringInSliceOptionalDefault([]string{"Public", "Private"}, "Public"),
						},
					},
				},
			},
		},
	}
}
