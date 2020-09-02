package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaIAMSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"allow_container_registry": schemaBoolOptionalComputed(),
				"legacy":                   schemaBoolOptionalComputed(),
			},
		},
	}
}
