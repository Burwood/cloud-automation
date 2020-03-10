#!/usr/bin/env bash

# Create json parsor function
function jsonValue() {
KEY=$1
num=$2
awk -F"[,:}]" '{for(i=1;i<=NF;i++){if($i~/'$KEY'\042/){print $(i+1)}}}' | tr -d '"' | sed -n ${num}p
}

# Get aws organizations accounts
aws organizations list-accounts > aws_accts_json

# Export AWS Account ID's to output and set as an array
cat aws_accts_json | jsonValue Id > aws_id_output
while IFS= read -r line;
  do printf '%s ' "$line" >> aws_accts_array ;
done < aws_id_output

# Run inspec tests based on Account ID array
accounts_array=$(cat aws_accts_array)
for i in $accounts_array;
do
  if [ "$i" = $i ] ;
  then
    aws_account_id=${i}
    echo " starting inspec run - !" $i
  else
    exit 1
  fi

# Set path to location of inspec.yml to change the value of the environment and account
file="/Users/rodneybizzell/burwood/inspec-aws/uchi-inspec-policy/inspec.yml"
echo "${file}"
sed -i "" "s|aws-env|$i|g; s|aws-acct-id|$i|g" $file
echo "changed file"

# Set env variable for profile
export AWS_PROFILE=burwood
aws_list=$(aws configure list)
echo "$aws_list"
dir="/tmp"
echo "${dir}"
date=$(date +"%m_%d_%Y %T")
aws_account="burwood"

# Run inpec tests
inspec exec uchi-inspec-policy -t aws:// --reporter cli json:"${dir}/uchi_${aws_account}_${date}.json"

# Copy test results to s3
aws s3 cp ${dir}/uchi_"${aws_account}_${date}.json" s3://burwood-cdistest/
echo "copied data to s3 bucket"
if [ $? -eq 0 ]
then
  echo "Copy to s3 bucket complete... "
else
  echo "Copy to s3 bucket failed... " >&2
fi


# Reset inspec.yaml values
sed -i "" "s|$i|aws-env|g; s|$i|aws-acct-id|g" $file
done

# Clean up Account ID array
rm aws_accts_array aws_accts_json aws_id_output







