package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaAWSConfig() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"access_key":              schemaStringOptional(), //AWS_ACCESS_KEY_ID
				"secret_key":              schemaStringOptional(), //AWS_SECRET_ACCESS_KEY
				"profile":                 schemaStringOptional(), // AWS_PROFILE
				"assume_role":             schemaAWSAssumeRoleConfig(),
				"shared_credentials_file": schemaStringOptional(), //AWS_SHARED_CREDENTIALS_FILE
				"token":                   schemaStringOptional(), //AWS_SESSION_TOKEN
				"region":                  schemaStringOptional(), //AWS_REGION AWS_DEFAULT_REGION
			},
		},
	}
}
