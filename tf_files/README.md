# TL;DR

Terraform rules for bringing up cloud resources in different stacks.  Use the [gen3](../gen3/README.md) 
helper scripts to simplify running terraform and other
devops tasks.

## Organization

We typically run terraform from a "state folder" where a local state for a particular VPC is saved, and reference one of the *tf_files/* subfolders to specify the cloud resources that make up the VPC, so something like this:

```
$ cd state/folder
$ terraform init --backend-config ./vars1.tfvars --backend-config ./vars2.tfvars ~/Code/cloud-automation/tf_files/SUBFOLDER
```

* tf_files/aws - rules for resources in an AWS commons VPC
* tf_files/configs - templates supporting tf_files/aws
* tf_files/aws_user_vpc - rules for resources in an AWS VPC for user VM's
* tf_files/modules - terraform modules that can be shared between different stacks

The [gen3 helper scripts](../gen3/README.md) standardize and simplify this process.

## tf_files/aws/commons

Resources for a gen3 commons in an AWS VPC.
```
gen3 workon cdistest devplanetv1
```

## tf_files/aws/data_bucket

Create a data bucket and associated IAM roles, policies, and profiles.
```
gen3 workon gen3 vpcname_projname_databucket
```

## tf_files/aws/rds_snapshot

Terraform resources tracking snapshots of the RDS resources in a commons.
```
gen3 workon devplanetv1_snapshot
```

## tf_files/aws/user_vpc

Resources for a user VPC in AWS - which provides a network for creating user VM's
```
$ gen3 workon gen3 commons_user
```

## tf_files/aws/csoc_admin_vm

Setup the *admin vm* in the CSOC account for a particular child account.
```
$ gen3 workon csoc cdistest_adminvm
```

## tf_files/aws/utility_vm

Setup and utilityVM that would foolow a bootstrap scrip.
```
$ gen3 workon <profile> <commons_name>_es
```

## tf_files/aws/commons_vpc_es

Setup an ElasticSearch cluster for arranger to access it.
```
$ gen3 workon <profile> <commons name>_es
```

## tf_files/aws/modules

Terraform code shared as modules.

