package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaEtcdClusterSpec() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": schemaStringRequired(),
				//"provider": schemaStringInSliceOptional([]string{"Manager", "Legacy"}),
				"etcd_member": {
					Type:     schema.TypeList,
					Required: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name":             schemaStringRequired(),
							"instance_group":   schemaStringRequired(),
							"volume_type":      schemaStringOptional(),
							"kms_key_id":       schemaStringOptional(),
							"volume_iops":      schemaIntOptional(),
							"volume_size":      schemaIntOptional(),
							"encrypted_volume": schemaBoolOptional(),
						},
					},
				},
				"version":                 schemaStringOptional(),
				"image":                   schemaStringOptional(),
				"enable_etcd_tls":         schemaBoolOptionalComputed(),
				"enable_tls_auth":         schemaBoolOptionalComputed(),
				"leader_election_timeout": schemaIntOptional(),
				"heartbeat_interval":      schemaIntOptional(),
				"backups": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"backup_store": schemaStringOptional(),
							"image":        schemaStringOptional(),
						},
					},
				},
				"manager": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"image": schemaStringOptional(),
						},
					},
				},
			},
		},
	}
}
