variable "role_name" {
  description = "The name of the IAM role"
  type        = string
}

variable "RoleTrustedPrincipalId" {
  description = "The trusted principal ID"
  type        = string
}

variable "RoleExternalId" {
  description = "The external ID for assume role"
  type        = string
}
