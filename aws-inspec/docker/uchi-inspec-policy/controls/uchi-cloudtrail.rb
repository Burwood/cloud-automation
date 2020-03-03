control "uchi-cis-aws-foundations-2.1" do
  title "Ensure CloudTrail is enabled in all regions"
  desc  "AWS CloudTrail is a web service that records AWS API calls for your
account and delivers log files to you"
  tag impact_score: 0.3
  tag nist_csf: ['PR.DS-1','PR.DS-2']
  tag cis_aws: ['2.1']
  tag nist_800_53: ['SC-8']
  tag nist_subcategory: ['PR.DS-2']
  tag env: ['test']
  tag aws_account_id: ['866696907']


  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      it { should be_multi_region_trail }
      it { should be_logging }
    end
  end
end


control "uchi-cis-aws-foundations-2.7" do
  title "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
  desc  "AWS CloudTrail is a web service that records AWS API calls for an
account and makes those logs available to users and resources in accordance
with IAM policies"
  tag impact_score: 0.7
  tag nist_csf: ['PR.DS-1','PR.DS-2']
  tag cis_aws: ['2.7']
  tag nist_800_53: ['SC-8']
  tag nist_subcategory: ['PR.DS-2']
  tag env: ['test']
  tag aws_account_id: ['866696907']


 describe aws_cloudtrail_trails do
   it { should exist }
 end

 aws_cloudtrail_trails.trail_arns.each do |trail|
   describe aws_cloudtrail_trail(trail) do
     its('kms_key_id') { should_not be_nil }
   end
 end
end

control "uchi-cis-aws-foundation-3.1" do
  title "Ensure a log metric filter and alarm exist for unauthorized API calls"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.7
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.1']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end
end

describe.one do
  aws_cloudtrail_trails.trail_arns.each do |trail|

    describe aws_cloudtrail_trail(trail) do
      its ('cloud_watch_logs_log_group_arn') { should_not be nil }

    end
  end
end


control "uchi-cis-aws-foundations-3.9" do
  title "Ensure a log metric filter and alarm exist for AWS Config
configuration changes"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.7
  tag nist_csf: ['ID.AM-1','PR.DS-3']
  tag cis_aws: ['3.9']
  tag nist_800_53: ['AU-12']
  tag nist_subcategory: ['DE.CM.1']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.8" do
  title "Ensure a log metric filter and alarm exist for S3 bucket policy
changes"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms "
  tag impact_score: 0.3
  tag nist_csf: ['PR.PT-1','PR.DS-5']
  tag cis_aws: ['3.8']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['PR.DS-5']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.7" do
  title "Ensure a log metric filter and alarm exist for disabling or scheduled
deletion of customer created CMKs"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.7
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.7']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.6" do
  title "Ensure a log metric filter and alarm exist for AWS Management Console
authentication failures"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.7
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.6']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.5" do
  title "Ensure a log metric filter and alarm exist for CloudTrail
configuration changes"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.3
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.5']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.4" do
  title "Ensure a log metric filter and alarm exist for IAM policy changes"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.3
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.4']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.3" do
  title "Ensure a log metric filter and alarm exist for usage of root account"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.3
  tag nist_csf: ['PR.PT-1','PR.DS-4']
  tag cis_aws: ['3.3']
  tag nist_800_53: ['AU-12']
  tag nist_subcategory: ['PR.PT-1']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.2" do
  title "Ensure a log metric filter and alarm exist for Management Console
sign-in without MFA"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.3
  tag nist_csf: ['PR.PT-1','PR.DS-4']
  tag csc_control: ['5.5','6.0']
  tag cis_aws: ['3.2']
  tag nist_800_53: ['AU-12']
  tag nist_subcategory: ['PR.PT-1']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.14" do
  title "Ensure a log metric filter and alarm exist for VPC changes"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.3
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.14']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.13" do
  title "Ensure a log metric filter and alarm exist for route table changes"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.3
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.13']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.12" do
  title "Ensure a log metric filter and alarm exist for changes to network
gateways"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms. Network gateways are required to send/receive traffic to a
destination outside of a VPC"
  tag impact_score: 0.3
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.12']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']



describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.11" do
  title "Ensure a log metric filter and alarm exist for changes to Network
Access Control Lists (NACL)"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.7
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.11']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-3.10" do
  title "Ensure a log metric filter and alarm exist for security group changes"
  desc "Real-time monitoring of API calls can be achieved by directing
CloudTrail Logs to CloudWatch Logs and establishing corresponding metric
filters and alarms"
  tag impact_score: 0.7
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['3.10']
  tag nist_800_53: ['SI-4']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


 describe aws_cloudtrail_trails do
    it { should exist }
  end

  describe.one do
    aws_cloudtrail_trails.trail_arns.each do |trail|

      describe aws_cloudtrail_trail(trail) do
        its ('cloud_watch_logs_log_group_arn') { should_not be_nil }
      end

      trail_log_group_name = aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.scan(/log-group:(.+):/).last.first unless aws_cloudtrail_trail(trail).cloud_watch_logs_log_group_arn.nil?

      next if trail_log_group_name.nil?

      pattern = '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'

      describe aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name) do
        it { should exist }
      end

      metric_name = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_name
      metric_namespace = aws_cloudwatch_log_metric_filter(pattern: pattern, log_group_name: trail_log_group_name).metric_namespace
      next if metric_name.nil? && metric_namespace.nil?

      describe aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ) do
        it { should exist }
        its ('alarm_actions') { should_not be_empty }
      end

      aws_cloudwatch_alarm(
        metric_name: metric_name,
        metric_namespace: metric_namespace
      ).alarm_actions.each do |sns|
        describe aws_sns_topic(sns) do
          it { should exist }
          its('confirmed_subscription_count') { should_not be_zero }
        end
      end
    end
  end
end

control "uchi-cis-aws-foundations-2.2" do
  title "Ensure CloudTrail log file validation is enabled"
  desc "CloudTrail log file validation creates a digitally signed digest file
containing a hash of each log that CloudTrail writes to S3"
  tag impact_score: 0.7
  tag nist_csf: ['PR.PT-1','DE.AE-3']
  tag cis_aws: ['2.2']
  tag nist_800_53: ['AU-4']
  tag nist_subcategory: ['PR.PT-1']
  tag env: ['test']
  tag aws_account_id: ['866696907']


   describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      it { should be_log_file_validation_enabled }
    end
  end
end

control "uchi-cis-aws-foundations-2.3" do
  title "Ensure the S3 bucket CloudTrail logs to is not publicly accessible"
  desc "CloudTrail logs a record of every API call made in your AWS account
these logs file are stored in an S3 bucket"
  tag impact_score: 0.3
  tag nist_csf: ['PR.PT-1','DE.AE-3']
  tag cis_aws: ['2.3']
  tag nist_800_53: ['AU-9']
  tag nist_subcategory: ['PR.PT-1']
  tag env: ['test']
  tag aws_account_id: ['866696907']


  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    bucket_name = aws_cloudtrail_trail(trail).s3_bucket_name
      describe aws_s3_bucket(bucket_name) do
        it { should_not be_public }
      end
    end
  end


control  "uchi-cis-aws-foundations-2.4" do
  title "Ensure CloudTrail trails are integrated with CloudWatch Logs"
  desc "AWS CloudTrail is a web service that records AWS API calls made in a
given AWS account"
  tag impact_score: 0.3
  tag nist_csf: ['ID.AM-4','DE.CM-7']
  tag cis_aws: ['2.4']
  tag nist_800_53: ['AU-12']
  tag nist_subcategory: ['DE.CM-7']
  tag env: ['test']
  tag aws_account_id: ['866696907']


  describe aws_cloudtrail_trails do
    it { should exist }
  end

  aws_cloudtrail_trails.trail_arns.each do |trail|
    describe aws_cloudtrail_trail(trail) do
      its('cloud_watch_logs_log_group_arn') { should_not be_nil }
      its('delivered_logs_days_ago') { should cmp <= 1 }
    end
  end
end



   



