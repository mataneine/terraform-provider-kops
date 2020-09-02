package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaHookSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name":           schemaStringRequired(),
				"disabled":       schemaBoolOptionalComputed(),
				"manifest":       schemaStringRequired(),
				"before":         schemaStringSliceOptional(),
				"requires":       schemaStringSliceOptional(),
				"roles":          schemaStringSliceRequired(),
				"exec_container": schemaExecContainerAction(),
			},
		},
	}
}
