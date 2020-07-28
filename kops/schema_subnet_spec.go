package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaClusterSubnetSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"provider_id": schemaStringOptional(),
				"name":        schemaStringRequired(),
				"zone":        schemaStringRequired(),
				"cidr":        schemaCIDRStringRequired(),
				"type":        schemaStringInSliceRequired([]string{"Public", "Private", "Utility"}),
			},
		},
	}
}
