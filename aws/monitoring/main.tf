terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "4.29.0"
    }
  }
}

provider "aws" {}

resource "aws_sns_topic" "monitoring" {
  name              = "cyscale-monitoring"
  kms_master_key_id = "alias/aws/sns"

  tags = {
    owner = var.email
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.monitoring.arn
  protocol  = "email"
  endpoint  = var.email
}

# Control: 4.1 Ensure a log metric filter and alarm exist for unauthorized API calls
module "unauthorized_api_calls" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "unauthorized_api_calls"
  namespace      = var.namespace
  pattern        = "{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")}"
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA
module "no_mfa_console_signin" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "no_mfa_console_signin"
  namespace      = var.namespace
  pattern        = "{($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\")}"
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.3 Ensure a log metric filter and alarm exist for usage of 'root' account
module "root_usage" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "root_usage"
  namespace      = var.namespace
  pattern        = "{$.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\"}"
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.4 Ensure a log metric filter and alarm exist for IAM policy changes
module "iam_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "iam_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
   {($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||
    ($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||
    ($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||
    ($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||
    ($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||
    ($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||
    ($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||
    ($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}
  PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes
module "cloudtrail_cfg_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "cloudtrail_cfg_changes"
  namespace      = var.namespace
  pattern        = "{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}"
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
module "console_signin_failure" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "console_signin_failure"
  namespace      = var.namespace
  pattern        = "{($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\")}"
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
module "disable_or_delete_cmk_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "disable_or_delete_cmk_changes"
  namespace      = var.namespace
  pattern        = "{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}"
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes
module "s3_bucket_policy_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "s3_bucket_policy_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
{($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) ||
($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) ||
($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) ||
($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) ||
($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }
PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes
module "aws_config_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "aws_config_changes"
  namespace      = var.namespace
  pattern        = "{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}"
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.10 Ensure a log metric filter and alarm exist for Security Group changes
module "security_group_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "security_group_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
{($.eventName = AuthorizeSecurityGroupIngress) ||
($.eventName = AuthorizeSecurityGroupEgress) ||
($.eventName = RevokeSecurityGroupIngress) ||
($.eventName = RevokeSecurityGroupEgress) ||
($.eventName = CreateSecurityGroup) ||
($.eventName = DeleteSecurityGroup)}
  PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.11 Ensure a log metric filter and alarm exist for changes to NACLs
module "nacl_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "nacl_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
{($.eventName = CreateNetworkAcl) ||
($.eventName = CreateNetworkAclEntry) ||
($.eventName = DeleteNetworkAcl) ||
($.eventName = DeleteNetworkAclEntry) ||
($.eventName = ReplaceNetworkAclEntry) ||
($.eventName = ReplaceNetworkAclAssociation)}
PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.12 Ensure a log metric filter and alarm exist for changes to network gateways
module "gateway_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "gateway_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
{($.eventName = CreateCustomerGateway) ||
($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) ||
($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) ||
($.eventName = DetachInternetGateway)}
PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.13 Ensure a log metric filter and alarm exist for route table changes
module "route_table_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "route_table_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
{($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) ||
($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation)||
($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) ||
($.eventName = DisassociateRouteTable) }
PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.14 Ensure a log metric filter and alarm exist for VPC changes
module "vpc_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "vpc_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
 {($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) ||
  ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) ||
  ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) ||
  ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) ||
  ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink)}
PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}

# Control: 4.15 Ensure a log metric filter and alarm exists for AWS Organizations changes
module "org_changes" {
  source = "../modules/monitoring-alarm"

  log_group_name = var.log_group_name
  name           = "org_changes"
  namespace      = var.namespace
  pattern        = <<PATTERN
 {($.eventSource = organizations.amazonaws.com) && 
  (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || 
  ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganizationalUnit") || 
  ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || 
  ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || 
  ($.eventName = "DeletePolicy") || ($.eventName = "DetachPolicy") || 
  ($.eventName = "DisablePolicyType") || ($.eventName = "EnablePolicyType") || 
  ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || 
  ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || 
  ($.eventName = "UpdatePolicy") || ($.eventName = "UpdateOrganizationalUnit"))}
PATTERN
  topic_arn      = aws_sns_topic.monitoring.arn
}
