variable "aws_region" { type = string, default = "us-east-1" }
variable "name" { type = string, default = "ai-redteam-harness" }
variable "environment" { type = string, default = "sandbox" }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "allowed_egress_cidrs" {
  description = "Explicit HTTPS egress destinations for scanner traffic. Empty by default (deny egress)."
  type        = list(string)
  default     = []
}
variable "image_tag" { type = string, default = "latest" }
variable "secret_arns" {
  description = "Existing Secrets Manager ARNs injected into the task. Secret values are never managed by this module."
  type        = map(string)
  default     = {}
}
