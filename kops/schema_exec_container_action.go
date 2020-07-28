package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaExecContainerAction() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"image":       schemaStringRequired(),
				"command":     schemaStringSliceRequired(),
				"environment": schemaStringMap(),
			},
		},
	}
}
