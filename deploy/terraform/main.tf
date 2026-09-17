provider "aws" { region = var.aws_region }

data "aws_caller_identity" "current" {}

locals { prefix = "${var.name}-${var.environment}" }

resource "aws_ecr_repository" "harness" {
  name                 = local.prefix
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
}

resource "aws_cloudwatch_log_group" "harness" {
  name              = "/ecs/${local.prefix}"
  retention_in_days = 30
}

resource "aws_s3_bucket" "results" { bucket_prefix = "${local.prefix}-results-" }
resource "aws_s3_bucket_public_access_block" "results" {
  bucket                  = aws_s3_bucket.results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "results" {
  bucket = aws_s3_bucket.results.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
resource "aws_s3_bucket_versioning" "results" {
  bucket = aws_s3_bucket.results.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_policy" "results_tls" {
  bucket = aws_s3_bucket.results.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.results.arn, "${aws_s3_bucket.results.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_ecs_cluster" "harness" {
  name = local.prefix
  setting { name = "containerInsights", value = "enabled" }
}

resource "aws_iam_role" "execution" {
  name = "${local.prefix}-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole"
    }]
  })
}
resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "task" {
  name = "${local.prefix}-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17", Statement = [{
      Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" }, Action = "sts:AssumeRole"
    }]
  })
}
resource "aws_iam_role_policy" "task" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = concat([
      {
        Effect = "Allow", Action = ["s3:PutObject", "s3:GetObject"],
        Resource = "${aws_s3_bucket.results.arn}/*"
      }
    ], length(var.secret_arns) == 0 ? [] : [{
      Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = values(var.secret_arns)
    }])
  })
}

resource "aws_security_group" "task" {
  name_prefix = "${local.prefix}-"
  description = "Egress-only security group for AI red-team harness"
  vpc_id      = var.vpc_id
  dynamic "egress" {
    for_each = length(var.allowed_egress_cidrs) == 0 ? [] : [1]
    content {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = var.allowed_egress_cidrs
      description = "Explicit HTTPS scanner egress"
    }
  }
}

resource "aws_ecs_task_definition" "harness" {
  family                   = local.prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name                   = "harness"
    image                  = "${aws_ecr_repository.harness.repository_url}:${var.image_tag}"
    essential              = true
    readonlyRootFilesystem = true
    user                   = "app"
    command                = ["run", "config/campaign.example.yaml", "--output-dir", "/tmp/results"]
    linuxParameters = { initProcessEnabled = true, capabilities = { drop = ["ALL"] } }
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.harness.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "harness"
      }
    }
    secrets = [for name, arn in var.secret_arns : { name = name, valueFrom = arn }]
  }])
}
