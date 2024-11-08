output "security_audit_attachment" {
  value = aws_iam_role_policy_attachment.security_audit_attachment
  description = "The attachment for the SecurityAudit policy"
}

output "read_only_policy" {
  value = aws_iam_role_policy.read_only_policy
  description = "The inline ReadOnlyPolicy"
}
