package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"terraform-provider-kops/kops"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: kops.Provider})
}
