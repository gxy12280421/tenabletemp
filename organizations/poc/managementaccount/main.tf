module "roles" {
  source              = "../modules/roles"
  role_name           = var.role_name
  RoleTrustedPrincipalId = var.RoleTrustedPrincipalId
  RoleExternalId      = var.RoleExternalId
}

module "policies" {
  source                   = "../modules/policies"
  role_name                = module.roles.role.name
  RoleMonitoringPolicyEnabled = var.RoleMonitoringPolicyEnabled
  RoleRemediationPolicyEnabled = var.RoleRemediationPolicyEnabled
  RoleDataAnalysisScanningPolicyEnabled = var.RoleDataAnalysisScanningPolicyEnabled
  RoleVirtualMachineScanningPolicyEnabled = var.RoleVirtualMachineScanningPolicyEnabled
}
