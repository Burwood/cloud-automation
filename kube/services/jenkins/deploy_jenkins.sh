#!/bin/bash
#
# Just a little helper for deploying jenkins onto k8s the first time
#

set -e
echo 'Registering Jenkins with k8s'

#
# Assume Jenkins should use the credentials harvested by terraform,
# then copied into ~/.aws/credentials by kube-up.sh ...
#
if [ -f ~/.aws/credentials ]; then
  aws_access_key_id="$(cat ~/.aws/credentials | grep aws_access_key_id | sed 's/.*=//' | sed 's/\s*//g' | head -1)"
  aws_secret_access_key="$(cat ~/.aws/credentials | grep aws_secret_access_key | sed 's/.*=//' | sed 's/\s*//g' | head -1)"
fi
if [ -z "$aws_access_key_id" -o -z "$aws_secret_access_key" ]; then
  echo 'WARNING: not configuring jenkins - could not extract secrets from ~/.aws/credentials'
else
  kubectl create secret generic jenkins-secret "--from-literal=aws_access_key_id=$aws_access_key_id" "--from-literal=aws_secret_access_key=$aws_secret_access_key"
  kubectl apply -f services/jenkins/serviceaccount.yaml
  kubectl apply -f services/jenkins/role-devops.yaml
  kubectl apply -f services/jenkins/rolebinding-devops.yaml
  
  kubectl apply -f services/jenkins/jenkins-deploy.yaml
  kubectl apply -f services/jenkins/jenkins-service.yaml
fi