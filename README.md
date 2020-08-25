# terraform-provider-kops - WIP

[![Build Status](https://travis-ci.org/wandera/terraform-provider-kops.svg?branch=master)](https://travis-ci.org/wandera/terraform-provider-kops)
[![Go Report Card](https://goreportcard.com/badge/github.com/wandera/terraform-provider-kops)](https://goreportcard.com/report/github.com/wandera/terraform-provider-kops)
[![GitHub release](https://img.shields.io/github/release/wandera/terraform-provider-kops.svg)](https://github.com/wandera/terraform-provider-kops/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/wandera/terraform-provider-kops/blob/master/LICENSE)

# Road to 0.0.1-alpha
- [x] Implement kops/v1alpha2/Cluster flattening to TF state
- [x] Implement kops_cluster resource state sync
- [ ] Implement kops/v1alpha2/InstanceGroup flattening to TF state
- [x] Implement kops_instance_group resource state sync
- [ ] Cover flattening/expanding of state by UTs
- [x] Fill in spec defaults using `cloudup` package
- [ ] Deep validate spec using `cloudup` package
- [ ] Run create cluster cmd

# Roadmap
- [ ] Run rolling-update cluster cmd automatically
- [ ] Implement Cluster datasource
- [ ] Implement InstanceGroup datasource
- [ ] Implement Keystore datasource
- [ ] Implement Secretstore datasource
- [ ] Implement SSHSecretstore datasource
- [ ] Add e2e tests

# Usage

### Checkout 
```
git clone git@github.com:mataneine/terraform-provider-kops.git
cd terraform-provider-kops
git checkout kops-1.16.0
```

### Build
```
go mod vendor
cp models/bindata.go vendor/k8s.io/kops/upup/models
go build -mod vendor -v -o ~/.terraform.d/plugins/terraform-provider-kops
```

### Provider
```hcl
provider "kops" {
  state_store = "s3://kops.train.state"
}
```

### Cluster
```hcl
resource "kops_cluster" "my-kops-cluster" {

  sshkey_path = "/Users/<yourusername>/.ssh/id_rsa.pub"

  name = "my-kops-cluster.k8s.local"

  channel = "stable"
  cloud_provider      = "aws"
  cluster_dnsdomain   = "cluster.local"
  config_store = "s3://kops.train.state/my-kops-cluster.k8s.local"

  authorization = "RBAC"

  api {
    dns = false
    load_balancer {
      type = "Public"
    }
  }

  iam {
    allow_container_registry = true
    legacy = false
  }


  kubernetes_version  = "1.18.6"

  network_cidr        = "172.20.0.0/16"
  non_masquerade_cidr = "172.20.0.0/16"

  topology {
      dns {
        type = "Public"
      }
  }


  service_cluster_iprange = "172.20.0.0/19"

  networking {
      name = "amazonvpc"
  }

  subnet {
      cidr = "172.20.32.0/19"
      name = "us-east-1a"
      type = "Public"
      zone = "us-east-1a"
  }

  subnet {
      cidr = "172.20.64.0/19"
      name = "us-east-1b"
      type = "Public"
      zone = "us-east-1b"
  }

  subnet {
      cidr = "172.20.96.0/19"
      name = "us-east-1c"
      type = "Public"
      zone = "us-east-1c"
  }

   etcd_cluster {
      name            = "main"
      enable_etcd_tls = "true"
      enable_tls_auth = "true"
      version         = "3.3.13"

      etcd_member {
        name             = "a"
        instance_group   = "master-us-east-1a"
      }

      backups {
        backup_store = "s3://kops.train.state/my-kops-cluster.k8s.local/backups/etcd/main"
      }
  }

  etcd_cluster {
      name            = "events"
      enable_etcd_tls = "true"
      enable_tls_auth = "true"
      version         = "3.3.13"

      etcd_member {
        name             = "a"
        instance_group   = "master-us-east-1a"
      }

      backups {
        backup_store = "s3://kops.train.state/my-kops-cluster.k8s.local/backups/etcd/events"
      }
  }

  instancegroup {
    name         = "master-us-east-1a"
    image        = "099720109477/ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200716"
    machine_type = "t3.medium"
    min_size     = 1
    max_size     = 1
    cloud_labels = {
      "kops.k8s.io/instancegroup" = "master-us-east-1a"
      "k8s.io/cluster-autoscaler/enabled" = true
      "kubernetes.io/cluster/zone"     = "owned"
    }
    node_labels = {
      "kops.k8s.io/instancegroup" = "master-us-east-1a"
    }
    role        = "Master"
    zones       = ["us-east-1a"]
    subnets     = ["us-east-1a"]
  }

  instancegroup {
    name                       = "nodes"
    image                      = "099720109477/ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200716"
    machine_type               = "t3.medium"
    min_size                   = 2
    max_size                   = 2
    node_labels = {
      "kubelet.kubernetes.io/role"     = "Node"
      "node-role.kubernetes.io/worker" = "true"
      "kops.k8s.io/instancegroup" = "nodes"
    }
    role        = "Node"
    zones       = ["us-east-1a", "us-east-1b", "us-east-1c"]
    subnets     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  }

  instancegroup {
    name                       = "nodes-add"
    image                      = "099720109477/ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200716"
    machine_type               = "t3.medium"
    min_size                   = 2
    max_size                   = 2
    node_labels = {
      "kubelet.kubernetes.io/role"     = "Node"
      "node-role.kubernetes.io/worker" = "true"
      "kops.k8s.io/instancegroup" = "nodes"
    }
    role        = "Node"
    zones       = ["us-east-1a", "us-east-1b", "us-east-1c"]
    subnets     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  }

  instancegroup {
    name                       = "nodes-more"
    image                      = "099720109477/ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20200716"
    machine_type               = "t3.medium"
    min_size                   = 2
    max_size                   = 2
    node_labels = {
      "kubelet.kubernetes.io/role"     = "Node"
      "node-role.kubernetes.io/worker" = "true"
      "kops.k8s.io/instancegroup" = "nodes"
    }
    role        = "Node"
    zones       = ["us-east-1a", "us-east-1b", "us-east-1c"]
    subnets     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  }

}
```
