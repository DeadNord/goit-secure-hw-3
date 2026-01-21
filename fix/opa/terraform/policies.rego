package terraform

deny[msg] {
  # tfplan.json (terraform show -json)
  some r
  r := input.resource_changes[_]
  r.type == "aws_security_group"
  r.change.after.ingress[_].cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf("Terraform: заборонено 0.0.0.0/0 для ingress у %v", [r.name])
}
