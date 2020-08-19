package kops

import (
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kops/pkg/apis/kops"
	"k8s.io/kops/pkg/assets"
	"k8s.io/kops/pkg/client/simple"
	"k8s.io/kops/pkg/commands"
	"k8s.io/kops/pkg/kubeconfig"
	"k8s.io/kops/pkg/resources"
	"k8s.io/kops/pkg/resources/ops"
	"k8s.io/kops/upup/pkg/fi"
	"k8s.io/kops/upup/pkg/fi/cloudup"
	"k8s.io/kops/upup/pkg/fi/utils"
)

func resourceCluster() *schema.Resource {
	return &schema.Resource{
		Create: resourceClusterCreate,
		Read:   resourceClusterRead,
		Update: resourceClusterUpdate,
		Delete: resourceClusterDelete,
		Exists: resourceClusterExists,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: schemaCluster(),
	}
}

func resourceClusterCreate(d *schema.ResourceData, m interface{}) error {
	clientset := m.(*ProviderConfig).clientset

	cluster, err := clientset.CreateCluster(expandCluster(d))
	if err != nil {
		return err
	}
	cluster, err = clientset.GetCluster(cluster.Name)
	if err != nil {
		return err
	}

	channel, err := cloudup.ChannelForCluster(cluster)
	if err != nil {
		return err
	}

	instanceGroups := expandInstanceGroup(d)
	for _, instanceGroup := range instanceGroups {
		_, err = clientset.InstanceGroupsFor(cluster).Create(instanceGroup)
		if err != nil {
			break
		}
		fullInstanceGroup, err := cloudup.PopulateInstanceGroupSpec(cluster, instanceGroup, channel)
		if err != nil {
			break
		}
		_, err = clientset.InstanceGroupsFor(cluster).Update(fullInstanceGroup)
		if err != nil {
			break
		}
	}
	if err != nil {
		return err
	}

	sshCredentialStore, err := clientset.SSHCredentialStore(cluster)
	if err != nil {
		return err
	}
	sshkeyPath := d.Get("sshkey_path").(string)
	f := utils.ExpandPath(sshkeyPath)
	pubKey, err := ioutil.ReadFile(f)
	if err != nil {
		return fmt.Errorf("error reading SSH key file %q: %v", f, err)
	}
	err = sshCredentialStore.AddSSHPublicKey(fi.SecretNameSSHPrimary, pubKey)
	if err != nil {
		return fmt.Errorf("error adding SSH public key: %v", err)
	}
	if err := cloudup.PerformAssignments(cluster); err != nil {
		return err
	}

	cluster, err = clientset.GetCluster(cluster.Name)
	if err != nil {
		return err
	}

	assetBuilder := assets.NewAssetBuilder(cluster, "")
	fullCluster, err := cloudup.PopulateClusterSpec(clientset, cluster, assetBuilder)
	if err != nil {
		return err
	}

	_, err = clientset.UpdateCluster(fullCluster, nil)
	if err != nil {
		return err
	}

	apply := &cloudup.ApplyClusterCmd{
		Cluster:        cluster,
		Clientset:      clientset,
		TargetName:     cloudup.TargetDirect,
		InstanceGroups: instanceGroups,
		LifecycleOverrides: map[string]fi.Lifecycle{
			"IAMRole":                "ExistsAndWarnIfChanges",
			"IAMRolePolicy":          "ExistsAndWarnIfChanges",
			"IAMInstanceProfileRole": "ExistsAndWarnIfChanges",
		},
	}

	// if instanceGroupMaster.Spec.IAM != nil || instanceGroupNode.Spec.IAM != nil {
	// 	apply.LifecycleOverrides = map[string]fi.Lifecycle{
	// 		"IAMRole":                "ExistsAndWarnIfChanges",
	// 		"IAMRolePolicy":          "ExistsAndWarnIfChanges",
	// 		"IAMInstanceProfileRole": "ExistsAndWarnIfChanges",
	// 	}
	// }

	err = apply.Run()
	if err != nil {
		return err
	}

	_, err = buildKubecfg(cluster, m)

	d.SetId(cluster.Name)

	return resourceClusterRead(d, m)
}

func resourceClusterRead(d *schema.ResourceData, m interface{}) error {
	clientset := m.(*ProviderConfig).clientset

	cluster, err := getCluster(d, m)
	if err != nil {
		return err
	}

	instanceGroups, err := clientset.InstanceGroupsFor(cluster).List(v1.ListOptions{})
	if err != nil {
		return err
	}

	flattenCluster(d, cluster, instanceGroups)

	return nil
}

func ifInstanceGroupExists(cluster *kops.Cluster, ig *kops.InstanceGroup, clientset simple.Clientset) bool {
	instanceGroup, err := clientset.InstanceGroupsFor(cluster).Get(ig.ObjectMeta.Name, v1.GetOptions{})
	if err == nil && instanceGroup != nil {
		return true
	}

	return false
}

func resourceInstanceGroupHandle(d *schema.ResourceData, m interface{}) ([]*kops.InstanceGroup, error) {
	clientset := m.(*ProviderConfig).clientset
	instanceGroups := expandInstanceGroup(d)
	cluster := expandCluster(d)
	cluster, err := clientset.GetCluster(cluster.Name)
	if err != nil {
		return instanceGroups, err
	}
	channel, err := cloudup.ChannelForCluster(cluster)
	if err != nil {
		return instanceGroups, err
	}

	for _, instanceGroup := range instanceGroups {
		if !ifInstanceGroupExists(cluster, instanceGroup, clientset) {
			_, err = clientset.InstanceGroupsFor(cluster).Create(instanceGroup)
			if err != nil {
				break
			}
		}
		fullInstanceGroup, err := cloudup.PopulateInstanceGroupSpec(cluster, instanceGroup, channel)
		if err != nil {
			break
		}
		_, err = clientset.InstanceGroupsFor(cluster).Update(fullInstanceGroup)
		if err != nil {
			break
		}
	}

	if err != nil {
		return instanceGroups, err
	}

	return instanceGroups, nil
}

func resourceClusterUpdate(d *schema.ResourceData, m interface{}) error {
	if ok, _ := resourceClusterExists(d, m); !ok {
		d.SetId("")
		return nil
	}
	clientset := m.(*ProviderConfig).clientset
	cluster := expandCluster(d)

	instanceGroups, err := resourceInstanceGroupHandle(d, m)
	if err != nil {
		return err
	}

	assetBuilder := assets.NewAssetBuilder(cluster, "")
	fullCluster, err := cloudup.PopulateClusterSpec(clientset, cluster, assetBuilder)
	if err != nil {
		return err
	}

	_, err = clientset.UpdateCluster(fullCluster, nil)
	if err != nil {
		return err
	}

	apply := &cloudup.ApplyClusterCmd{
		Cluster:        cluster,
		Clientset:      clientset,
		TargetName:     cloudup.TargetDirect,
		InstanceGroups: instanceGroups,
		LifecycleOverrides: map[string]fi.Lifecycle{
			"IAMRole":                "ExistsAndWarnIfChanges",
			"IAMRolePolicy":          "ExistsAndWarnIfChanges",
			"IAMInstanceProfileRole": "ExistsAndWarnIfChanges",
		},
	}

	err = apply.Run()
	if err != nil {
		return err
	}

	return resourceClusterRead(d, m)
}

func resourceClusterDelete(d *schema.ResourceData, m interface{}) error {
	clientset := m.(*ProviderConfig).clientset
	cluster, err := getCluster(d, m)
	if err != nil {
		return err
	}

	cloud, err := cloudup.BuildCloud(cluster)
	if err != nil {
		return err
	}

	resourcesList, err := ops.ListResources(cloud, cluster.Name, "")
	if err != nil {
		return err
	}

	clusterResources := make(map[string]*resources.Resource)
	for k, resource := range resourcesList {
		if resource.Shared {
			continue
		}
		clusterResources[k] = resource
	}

	err = ops.DeleteResources(cloud, clusterResources)
	if err != nil {
		return err
	}

	err = clientset.DeleteCluster(cluster)
	if err != nil {
		return err
	}

	d.SetId("")

	return nil
}

func resourceClusterExists(d *schema.ResourceData, m interface{}) (bool, error) {
	_, err := getCluster(d, m)
	if err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func getCluster(d *schema.ResourceData, m interface{}) (*kops.Cluster, error) {
	clientset := m.(*ProviderConfig).clientset
	cluster, err := clientset.GetCluster(d.Id())
	return cluster, err
}

func buildKubecfg(cluster *kops.Cluster, m interface{}) (*kubeconfig.KubeconfigBuilder, error) {
	clientset := m.(*ProviderConfig).clientset
	keyStore, err := clientset.KeyStore(cluster)
	if err != nil {
		return nil, err
	}

	secretStore, err := clientset.SecretStore(cluster)
	if err != nil {
		return nil, err
	}

	conf, err := kubeconfig.BuildKubecfg(cluster, keyStore, secretStore, &commands.CloudDiscoveryStatusStore{}, clientcmd.NewDefaultPathOptions())

	if err != nil {
		return nil, err
	}

	conf.WriteKubecfg()
	return conf, nil
}