variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "account_id" {
  description = "AWS account ID"
  type        = string
  # No default - must be provided
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "github_repo" {
  description = "GitHub repository path (e.g., your-username/your-repo-name)"
  type        = string
  # No default - must be provided
}