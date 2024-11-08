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

variable "RoleMonitoringPolicyEnabled" {
  description = "Enable the Monitoring Policy"
  type        = bool
  default     = true
}

variable "RoleRemediationPolicyEnabled" {
  description = "Enable the Remediation Policy"
  type        = bool
  default     = true
}

variable "RoleDataAnalysisScanningPolicyEnabled" {
  description = "Enable the Data Scanning Policy"
  type        = bool
  default     = false
}

variable "RoleVirtualMachineScanningPolicyEnabled" {
  description = "Enable the EC2 Scanning Policy"
  type        = bool
  default     = false
}
