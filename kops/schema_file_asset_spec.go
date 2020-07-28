package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaFileAssetSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Computed: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name":      schemaStringRequired(),
				"path":      schemaStringRequired(),
				"content":   schemaStringRequired(),
				"is_base64": schemaBoolOptionalComputed(),
				"roles":     schemaStringSliceRequired(),
			},
		},
	}
}
