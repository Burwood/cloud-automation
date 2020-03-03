control "uchi-cis-aws-foundations-2.5" do
  title "Ensure AWS Config is enabled in all regions"
  desc "AWS Config is a web service that performs configuration management of
supported AWS resources within your account and delivers log files to you"
   tag impact_score: 0.3
   tag nist_csf: ['ID.AM-1','PR-DS-3','PR.PT-1','PR-DS-4']
   tag cis_aws: ['2.5']
   tag nist_800_53: ['AU-2','AU-6','CM-8','CM-6']
   tag nist_subcategory: ['ID.AM-1']
   tag env: ['test']
   tag aws_account_id: ['866696907']


  describe aws_config_recorder do
    it { should exist }
    it { should be_recording }
    it { should be_recording_all_resource_types }
    it { should be_recording_all_global_types }
  end

  describe aws_config_delivery_channel do
    it { should exist }
  end
end

#  if aws_config_delivery_channel.exists?
#    describe aws_config_delivery_channel do
#      its('s3_bucket_name') { should cmp config_delivery_channels[region]['s3_bucket_name'] }
#      its('sns_topic_arn') { should cmp config_delivery_channels[region]['sns_topic_arn'] }
#    end
#  end
#end