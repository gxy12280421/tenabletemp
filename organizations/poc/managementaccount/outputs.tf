output "role_arn" {
  value = module.roles.role.arn
  description = "The ARN of the IAM role"
}

output "policies" {
  value = module.policies
  description = "The attached policies"
}
