output "ecr_repository_url" { value = aws_ecr_repository.harness.repository_url }
output "ecs_cluster_name" { value = aws_ecs_cluster.harness.name }
output "task_definition_arn" { value = aws_ecs_task_definition.harness.arn }
output "results_bucket" { value = aws_s3_bucket.results.bucket }
output "security_group_id" { value = aws_security_group.task.id }
