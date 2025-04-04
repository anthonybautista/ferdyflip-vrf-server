provider "aws" {
  region = var.aws_region
}

# ECR Repository
resource "aws_ecr_repository" "app_repo" {
  name                 = "fulfillment-service"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "app_repo_policy" {
  repository = aws_ecr_repository.app_repo.name

  policy = jsonencode({
      rules = [
        {
          rulePriority = 1
          description  = "Keep only the 5 most recent images"
          selection = {
            tagStatus     = "any"
            countType     = "imageCountMoreThan"
            countNumber   = 5
          }
          action = {
            type = "expire"
          }
        }
      ]
    })
}

# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "fulfillment-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "app_log_group_1" {
  name              = "/ecs/fulfillment-service-primary"
  retention_in_days = 7  # Adjust retention period to manage costs
}

resource "aws_cloudwatch_log_group" "app_log_group_2" {
  name              = "/ecs/fulfillment-service-backup"
  retention_in_days = 7
}

# ECS Task Execution Role
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "ecsTaskExecutionRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Additional policy to allow reading from SSM Parameter Store and Secrets Manager
resource "aws_iam_policy" "secrets_access_policy" {
  name        = "ecs-secrets-access-policy"
  description = "Policy to allow ECS tasks to access secrets from SSM and Secrets Manager"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameters",
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:ssm:${var.aws_region}:${var.account_id}:parameter/fulfillment/*",
          "arn:aws:secretsmanager:${var.aws_region}:${var.account_id}:secret:fulfillment/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_secrets_policy" {
  role       = aws_iam_role.ecs_task_execution_role.name
  policy_arn = aws_iam_policy.secrets_access_policy.arn
}

# ECS Task Role - For permissions the running container needs
resource "aws_iam_role" "ecs_task_role" {
  name = "ecsTaskRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

# Use default VPC and subnets for simplicity
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Security Group - Minimal with only essential egress
resource "aws_security_group" "app_sg" {
  name        = "fulfillment-service-sg"
  description = "Security group for fulfillment service containers"
  vpc_id      = data.aws_vpc.default.id

  # No ingress rules since this is a listener service

  # Allow all outbound traffic (needed for pulling data)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VPC Endpoints for AWS services
resource "aws_vpc_endpoint" "secretsmanager" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type = "Interface"
  subnet_ids        = data.aws_subnets.default.ids
  security_group_ids = [aws_security_group.app_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssm" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type = "Interface"
  subnet_ids        = data.aws_subnets.default.ids
  security_group_ids = [aws_security_group.app_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type = "Interface"
  subnet_ids        = data.aws_subnets.default.ids
  security_group_ids = [aws_security_group.app_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type = "Interface"
  subnet_ids        = data.aws_subnets.default.ids
  security_group_ids = [aws_security_group.app_sg.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "logs" {
  vpc_id            = data.aws_vpc.default.id
  service_name      = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type = "Interface"
  subnet_ids        = data.aws_subnets.default.ids
  security_group_ids = [aws_security_group.app_sg.id]
  private_dns_enabled = true
}

# Read task definition files
locals {
  primary_task_def = templatefile("${path.module}/task-def-1.json", {
    AWS_ACCOUNT_ID = var.account_id
  })

  backup_task_def = templatefile("${path.module}/task-def-2.json", {
    AWS_ACCOUNT_ID = var.account_id
  })
}

# Register primary task definition
resource "aws_ecs_task_definition" "primary_task" {
  family                   = "fulfillment-service-primary"
  container_definitions    = jsonencode(jsondecode(local.primary_task_def).containerDefinitions)
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn
}

# Register backup task definition
resource "aws_ecs_task_definition" "backup_task" {
  family                   = "fulfillment-service-backup"
  container_definitions    = jsonencode(jsondecode(local.backup_task_def).containerDefinitions)
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn
}

# Create ECS Services - Primary Service
resource "aws_ecs_service" "primary_service" {
  name            = "fulfillment-service-primary"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.primary_task.arn  # This will be updated by the CI/CD pipeline
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.app_sg.id]
    assign_public_ip = false  # No need for public IP since it's a listener
  }
}

# Create ECS Services - Backup Service (delayed processing)
resource "aws_ecs_service" "backup_service" {
  name            = "fulfillment-service-backup"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.backup_task.arn  # This will be updated by the CI/CD pipeline
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = data.aws_subnets.default.ids
    security_groups  = [aws_security_group.app_sg.id]
    assign_public_ip = false  # No need for public IP since it's a listener
  }
}

# GitHub Actions IAM Role for CI/CD
resource "aws_iam_role" "github_actions_role" {
  name = "github-actions-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:ref:refs/heads/main"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "github_actions_policy" {
  name = "github-actions-policy"
  role = aws_iam_role.github_actions_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ]
        Resource = [
          aws_ecr_repository.app_repo.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecs:DescribeTaskDefinition",
          "ecs:RegisterTaskDefinition",
          "ecs:DescribeServices",
          "ecs:UpdateService"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecs:UpdateService"
        ]
        Resource = [
          "arn:aws:ecs:${var.aws_region}:${var.account_id}:service/${aws_ecs_cluster.main.name}/${aws_ecs_service.primary_service.name}",
          "arn:aws:ecs:${var.aws_region}:${var.account_id}:service/${aws_ecs_cluster.main.name}/${aws_ecs_service.backup_service.name}"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          aws_iam_role.ecs_task_execution_role.arn,
          aws_iam_role.ecs_task_role.arn
        ]
      }
    ]
  })
}

# Output the GitHub Actions role ARN to use in GitHub secrets
output "github_actions_role_arn" {
  value = aws_iam_role.github_actions_role.arn
  description = "The ARN of the IAM role for GitHub Actions"
}