package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaAWSAssumeRoleConfig() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"role_arn":     schemaStringOptional(),
				"session_name": schemaStringOptional(),
				"external_id":  schemaStringOptional(),
				"policy":       schemaStringOptional(),
			},
		},
	}
}
