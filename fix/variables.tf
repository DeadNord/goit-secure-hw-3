variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_id" {
  description = "Target VPC ID (явна межа ізоляції)"
  type        = string
}

variable "allowed_ingress_cidrs" {
  description = "CIDR allowlist для inbound HTTPS (PoLP на мережі)"
  type        = list(string)
  default     = []
}

variable "allowed_ingress_sg_ids" {
  description = "Allowlist SG (наприклад, ALB SG). Перевага над 0.0.0.0/0"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Теги для аудиту/інвентаризації (сигнал конфігурації)"
  type        = map(string)
  default     = {
    app = "user-api"
    env = "dev"
    owner = "team"
  }
}
