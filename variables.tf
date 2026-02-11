################################################################################
# AWS Provider
################################################################################

variable "access_key" {
  description = "AWS access key"
  type        = string
}

variable "secret_key" {
  description = "AWS secret key"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "AWS region"
  type        = string
}

################################################################################
# Policy Module
################################################################################

variable "project" {
  description = "Project name (e.g., ai_agent, data_platform)"
  type        = string
}

variable "environment" {
  description = "Environment name (e.g., dev, stg, prd)"
  type        = string
}

variable "policy_file" {
  description = "Path to policy YAML file (e.g., ai_agent/prd/infra-policy/vpc.yaml)"
  type        = string
  default     = null
}
