locals {
  filter_name = "${var.name}_metric"
  alarm_name  = "${var.name}_alarm"
}

resource "aws_cloudwatch_log_metric_filter" "filter" {
  name           = local.filter_name
  pattern        = var.pattern
  log_group_name = var.log_group_name

  metric_transformation {
    name      = local.filter_name
    namespace = var.namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm" {
  alarm_name          = local.alarm_name
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = local.filter_name
  namespace           = var.namespace
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [var.topic_arn]
}
