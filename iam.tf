resource "aws_iam_role" "ec2_ecr" {

  name = "${var.project_name}-ec2-ecr-role"

  assume_role_policy = jsonencode({

    Version = "2012-10-17"

    Statement = [

      {

        Effect = "Allow"

        Principal = {

          Service = "ec2.amazonaws.com"

        }

        Action = "sts:AssumeRole"

      }

    ]

  })

  tags = {

    Name = "${var.project_name}-ec2-ecr-role"

    Project = "CodeShield"

    Environment = var.environment

  }

}

resource "aws_iam_role_policy_attachment" "ec2_ecr_readonly" {

  role = aws_iam_role.ec2_ecr.name

  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"

}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {

  role = aws_iam_role.ec2_ecr.name

  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

}

resource "aws_iam_instance_profile" "ec2_ecr" {

  name = "${var.project_name}-ec2-ecr-profile"

  role = aws_iam_role.ec2_ecr.name

}