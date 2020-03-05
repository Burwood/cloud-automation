#!/usr/bin/env python
import boto3
import json

regions = [
    region["RegionName"]
    for region in boto3.client("ec2",'us-east-2').describe_regions()["Regions"]
]


for region in regions:
    ec2_client = boto3.client("ec2", region_name=region)
    log_client = boto3.client("logs", region_name=region)
    ec2 = boto3.resource("ec2", region_name=region)
    bucket = 'inspec-data'
    vpcs = [vpc.id for vpc in ec2.vpcs.all()]
    for vpc in vpcs:
        ec2_client = boto3.client("ec2", region_name=region)
        LogDestination = "arn:aws:s3:::%s/%s"%(bucket,vpc)
        
        try:
            print(
                f"Trying to enable flow logs for {vpc},"
                f" using {LogDestination} LogDestination"
            )
            ec2_client.create_flow_logs(
                    ResourceIds=[vpc],
                    ResourceType="VPC",
                    TrafficType="ALL",
                    LogDestinationType="s3",
                    LogDestination = LogDestination
                )
        except ClientError as e:
            if e.response["Error"]["Code"] == "FlowLogAlreadyExists":
                print(f"Flow logs is already enabled for {vpc}\n")
        else:
            print(f"Flow logs is successfully enabled for {vpc}\n")
