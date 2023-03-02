variable "namespace" {
  type        = string
  description = "The CloudWatch namespace. Read more here https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Namespace"
}

variable "log_group_name" {
  type        = string
  description = "The CloudWatch log group that will be monitored"
}

variable "email" {
  type        = string
  description = "The recipient of the alert notification (through SNS)"
}
