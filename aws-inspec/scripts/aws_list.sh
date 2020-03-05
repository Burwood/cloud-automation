#!/usr/bin/env bash
set -x
dir="/tmp/"
echo "${dir}"

aws-list-all query --region us-east-2 --directory "${dir}"

aws s3 cp ${dir} s3://inspec-data

echo "copied data to s3 bucket"

