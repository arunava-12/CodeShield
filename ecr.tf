resource "aws_ecr_repository" "codeshield" {
  name                 = "codeshield"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name        = "codeshield-ecr"
    Project     = "CodeShield"
    Environment = var.environment
  }
}

resource "aws_ecr_lifecycle_policy" "codeshield" {
  repository = aws_ecr_repository.codeshield.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep only the 5 most recent images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}