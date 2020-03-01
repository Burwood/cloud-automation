#!/usr/bin/env python
import boto3
import botocore
from datetime import datetime
from botocore.exceptions import ClientError
import json


s3 = boto3.resource('s3')
iam = boto3.client('iam')

paginator = iam.get_paginator('list_server_certificates')
response = list(paginator.paginate())


obj = s3.Object('inspec-data', 'server_certificates' + datetime.now().strftime("%d-%m-%Y_%I-%M-%S_%p"))
try:
    obj.put(Body=json.dumps(response))
except botocore.exceptions.ClientError as e:
    if e.response['Error']['Code'] == 'NoSuchUpload':
        print("Upload Failed")
    else:
        print("Upload Log Files")
