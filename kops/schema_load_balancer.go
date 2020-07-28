package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaLoadBalancer() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"load_balancer_name": schemaStringOptional(),
				"target_group_arn":   schemaStringOptional(),
			},
		},
	}
}
