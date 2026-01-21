provider "aws" {
  region = var.aws_region
}

resource "aws_security_group" "user_api" {
  name        = "user-api-sg"
  description = "Allow 443 only from allowlisted sources"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = length(var.allowed_ingress_cidrs) > 0 ? [1] : []
    content {
      description = "HTTPS from allowlisted CIDRs"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = var.allowed_ingress_cidrs
    }
  }

  dynamic "ingress" {
    for_each = length(var.allowed_ingress_sg_ids) > 0 ? [1] : []
    content {
      description     = "HTTPS from allowlisted SGs (наприклад, ALB)"
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      security_groups = var.allowed_ingress_sg_ids
    }
  }

  egress {
    description = "Outbound (звужуйте під реальні потреби)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "user-api-sg" })
}
