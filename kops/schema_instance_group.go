package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func schemaInstanceGroup() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"creation_timestamp":           schemaStringComputed(),
				"name":                         schemaStringRequired(),
				"role":                         schemaStringInSliceRequired([]string{"Master", "Node", "Bastion"}),
				"machine_type":                 schemaStringOptionalComputed(),
				"iam":                          schemaIAMProfileSpec(),
				"image":                        schemaStringOptionalComputed(),
				"max_price":                    schemaStringOptional(),
				"min_size":                     schemaIntOptional(),
				"max_size":                     schemaIntOptional(),
				"root_volume_iops":             schemaIntOptional(),
				"root_volume_optimization":     schemaBoolOptional(),
				"root_volume_size":             schemaIntOptional(),
				"root_volume_type":             schemaStringOptional(),
				"subnets":                      schemaStringSliceRequired(),
				"zones":                        schemaStringSliceRequired(),
				"cloud_labels":                 schemaStringMap(),
				"node_labels":                  schemaStringMap(),
				"additional_security_groups":   schemaStringSliceOptional(),
				"additional_user_data":         schemaUserData(),
				"associate_public_ip":          schemaBoolOptional(),
				"detailed_instance_monitoring": schemaBoolOptional(),
				"external_load_balancer":       schemaLoadBalancer(),
				"file_asset":                   schemaFileAssetSpec(),
				"hook":                         schemaHookSpec(),
				"kubelet":                      schemaKubeletConfigSpec(),
				"taints":                       schemaStringSliceOptional(),
			},
		},
	}
}
