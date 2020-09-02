package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaAccessSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"dns":           schemaBoolOptional(),
				"load_balancer": schemaLoadBalancerAccessSpec(),
			},
		},
	}
}
