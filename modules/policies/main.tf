resource "aws_iam_role_policy_attachment" "security_audit_attachment" {
  count      = var.RoleMonitoringPolicyEnabled ? 1 : 0
  role       = var.role_name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy" "read-only_policy" {
  count = var.RoleMonitoringPolicyEnabled ? 1 : 0
  role  = var.role_name
  name  = "Read-onlyPolicy"

  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Action    = [
          "acm:Describe*",
          "acm:List*",
          "aoss:BatchGet*",
          "aoss:List*",
          "autoscaling:Describe*",
          "batch:Describe*",
          "batch:List*",
          "bedrock:Get*",
          "bedrock:List*",
          "cloudformation:Describe*",
          "cloudformation:Get*",
          "cloudformation:List*",
          "cloudfront:Get*",
          "cloudfront:ListDistributions*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*",
          "cloudtrail:LookupEvents",
          "cloudwatch:Describe*",
          "cloudwatch:GetMetric*",
          "cloudwatch:ListMetrics",
          "cognito-idp:ListResourcesForWebACL",
          "cognito-sync:GetCognitoEvents",
          "config:Describe*",
          "dynamodb:Describe*",
          "dynamodb:List*",
          "ec2:Describe*",
          "ecr:Describe*",
          "ecr:GetRegistryScanningConfiguration",
          "ecr:GetRepositoryPolicy",
          "ecr:List*",
          "ecr:StartImageScan",
          "ecr-public:Describe*",
          "ecr-public:GetRepositoryPolicy",
          "ecr-public:List*",
          "ecs:Describe*",
          "ecs:List*",
          "eks:Describe*",
          "eks:List*",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticbeanstalk:Describe*",
          "elasticbeanstalk:List*",
          "elasticfilesystem:Describe*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "es:Describe*",
          "es:List*",
          "events:ListRules",
          "iam:Generate*",
          "iam:Get*",
          "iam:List*",
          "identitystore:Describe*",
          "inspector2:List*",
          "iot:GetTopicRule",
          "kms:Describe*",
          "kms:GetKey*",
          "kms:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "lambda:Get*Policy",
          "lambda:GetAccountSettings",
          "lambda:List*",
          "logs:Describe*",
          "organizations:Describe*",
          "organizations:List*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "redshift-serverless:List*",
          "redshift-serverless:Get*",
          "route53:Get*",
          "route53:List*",
          "route53domains:Get*",
          "route53domains:List*",
          "route53resolver:Get*",
          "route53resolver:List*",
          "s3:Describe*",
          "s3:GetAccessPoint*",
          "s3:GetAccountPublicAccessBlock",
          "s3:GetBucket*",
          "s3:GetEncryptionConfiguration",
          "s3:GetJobTagging",
          "s3:GetLifecycleConfiguration",
          "s3:ListAccessPoints",
          "s3:ListAllMyBuckets",
          "s3:ListBucketVersions",
          "s3:ListJobs",
          "sagemaker:Describe*",
          "sagemaker:List*",
          "secretsmanager:Describe*",
          "secretsmanager:GetResourcePolicy",
          "secretsmanager:List*",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "ssm:Describe*",
          "ssm:List*",
          "sso:Describe*",
          "sso:Get*",
          "sso:List*",
          "sso-directory:List*",
          "sso-directory:Search*",
          "sts:DecodeAuthorizationMessage",
          "tag:Get*",
          "timestream:List*",
          "timestream:Get*",
          "timestream:Describe*",
          "wafv2:Get*",
          "wafv2:List*"
        ]
        Resource = "*"
      },
      {
        Effect    = "Allow"
        Action    = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::elasticbeanstalk-*"
      },
      {
        Effect      = "Allow"
        Action      = "apigateway:Get*"
        NotResource = "arn:aws:apigateway:*::/apikeys*"
      }
    ]
  })
}


resource "aws_iam_role_policy" "data_scanning_policy" {
  count = var.RoleDataAnalysisScanningPolicyEnabled ? 1 : 0
  role  = var.role_name
  name  = "DataScanningPolicy"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "dynamodb:Scan",
          "kms:CreateGrant",
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:ReEncryptFrom",
          "kms:ReEncryptTo",
          "rds:CopyDBClusterSnapshot",
          "rds:CopyDBSnapshot",
          "rds:CreateDBClusterSnapshot",
          "rds:CreateDBSnapshot",
          "rds:ModifyDBClusterSnapshotAttribute",
          "rds:ModifyDBSnapshotAttribute",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = [
          "rds:AddTagsToResource"
        ]
        Resource = [
          "arn:aws:rds:*:*:cluster-snapshot:*",
          "arn:aws:rds:*:*:snapshot:*"
        ]
        Condition = {
          StringEquals = {
            "aws:RequestTag/TenableContext" = "DataAnalysis"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = [
          "rds:DeleteDBSnapshot"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "rds:snapshot-tag/TenableContext" = "DataAnalysis"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = [
          "rds:DeleteDBClusterSnapshot"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "rds:cluster-snapshot-tag/TenableContext" = "DataAnalysis"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_scanning_policy" {
  count = var.RoleVirtualMachineScanningPolicyEnabled ? 1 : 0
  role  = var.role_name
  name  = "Ec2ScanningPolicy"

  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Action    = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeImages"
        ]
        Resource  = "*"
        Effect    = "Allow"
        Sid       = "Ec2ScanningAccess"
      }
    ]
  })
}

resource "aws_iam_role_policy" "jit_policy" {
  count = var.RoleVirtualMachineScanningPolicyEnabled ? 1 : 0
  role   = var.role_name
  name   = "JitPolicy"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:ListRoles",
          "iam:ListPolicies"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:PutRolePolicy"
        ],
        Resource = "arn:${data.aws_partition.current.partition}:iam::*:role/aws-reserved/sso.amazonaws.com/*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:GetSAMLProvider",
          "iam:UpdateSAMLProvider"
        ],
        Resource = "arn:${data.aws_partition.current.partition}:iam::*:saml-provider/AWSSSO_*_DO_NOT_DELETE"
      },
      {
        Effect = "Allow"
        Action = [
          "sso:AttachManagedPolicyToPermissionSet",
          "sso:CreateAccountAssignment",
          "sso:CreatePermissionSet",
          "sso:DeleteAccountAssignment",
          "sso:DeletePermissionSet",
          "sso:Describe*",
          "sso:DetachManagedPolicyFromPermissionSet",
          "sso:Get*",
          "sso:List*",
          "sso:ProvisionPermissionSet",
          "sso:PutInlinePolicyToPermissionSet",
          "sso-directory:List*",
          "sso-directory:Search*"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_policy" {
  count = var.RoleVirtualMachineScanningPolicyEnabled && var.BucketEncryptionEnabled ? 1 : 0
  role  = var.role_name
  name  = "CloudTrailPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}",
          "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail_policy_with_kms" {
  count = var.RoleVirtualMachineScanningPolicyEnabled && !var.BucketEncryptionEnabled ? 1 : 0
  role  = var.role_name
  name  = "CloudTrailPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}",
          "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = "kms:Decrypt"
        Resource = var.cloudtrail_key_arn
      }
    ]
  })
}
