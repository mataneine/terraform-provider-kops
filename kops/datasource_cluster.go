package kops

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func dataSourceCluster() *schema.Resource {
	return &schema.Resource{
		Read: resourceClusterRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: schemaCluster(),
	}
}
