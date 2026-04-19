# AWS Security Patterns

Security patterns, common misconfigurations, and detection regexes for Amazon Web Services infrastructure. Covers IAM, S3, Lambda, Security Groups, KMS, CloudTrail, Secrets Manager, and RDS across Terraform, CloudFormation, and raw JSON/YAML configurations.

## IAM: Overly Permissive Policies

### Wildcard Actions in IAM Policies

```hcl
// VULNERABLE: IAM policy allows all actions on all resources
resource "aws_iam_policy" "admin" {
  name   = "full-admin"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

// SECURE: Least-privilege policy scoped to specific actions and resources
resource "aws_iam_policy" "s3_reader" {
  name   = "s3-reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }]
  })
}
```

**Detection regex:** `"Action"\s*:\s*"\*"|"Action"\s*:\s*\[\s*"\*"\s*\]`
**Severity:** error

### Missing Conditions on IAM Policies

```json
// VULNERABLE: No conditions — any principal matching the trust can assume this role
// Note: trust (assume-role) policies do NOT use the Resource element — it's implied by the role.
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"}
  }]
}

// SECURE: Conditions restrict usage by source IP, MFA, or external ID
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Condition": {
      "Bool": {"aws:MultiFactorAuthPresent": "true"},
      "IpAddress": {"aws:SourceIp": "203.0.113.0/24"}
    }
  }]
}
```

**Detection regex:** `"Effect"\s*:\s*"Allow"[^}]*"Action"\s*:\s*"sts:AssumeRole"(?![^}]*"Condition")`
**Severity:** warning

### Overly Permissive Trust Policies

```hcl
// VULNERABLE: Trust policy allows any AWS account to assume the role
resource "aws_iam_role" "cross_account" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = {"AWS": "*"}
    }]
  })
}

// SECURE: Trust restricted to specific account and role
resource "aws_iam_role" "cross_account" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = {"AWS": "arn:aws:iam::987654321098:role/SpecificRole"}
      Condition = {
        StringEquals = {"sts:ExternalId" = "unique-external-id"}
      }
    }]
  })
}
```

**Detection regex:** `"Principal"\s*:\s*\{\s*"AWS"\s*:\s*"\*"\s*\}|"Principal"\s*:\s*"\*"`
**Severity:** error

### iam:PassRole Abuse

```hcl
// VULNERABLE: PassRole with wildcard resource — can escalate to any role
resource "aws_iam_policy" "passrole_any" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = "*"
    }]
  })
}

// SECURE: PassRole restricted to specific role ARN
resource "aws_iam_policy" "passrole_scoped" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "iam:PassRole"
      Resource = "arn:aws:iam::123456789012:role/LambdaExecutionRole"
      Condition = {
        StringEquals = {"iam:PassedToService" = "lambda.amazonaws.com"}
      }
    }]
  })
}
```

**Detection regex:** `"Action"\s*:\s*"iam:PassRole"[^}]*"Resource"\s*:\s*"\*"`
**Severity:** error

## S3: Public Access and Encryption

### Public S3 Bucket via ACL

```hcl
// VULNERABLE: Public read ACL on S3 bucket
resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

// SECURE: Private ACL (default)
resource "aws_s3_bucket_acl" "private" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"
}
```

**Detection regex:** `acl\s*=\s*"public-read"|acl\s*=\s*"public-read-write"`
**Severity:** error

### Public S3 Bucket via Bucket Policy

```json
// VULNERABLE: Bucket policy grants access to anyone
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}

// SECURE: Bucket policy restricted to CloudFront OAI
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E1234"
    },
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::my-bucket/*"
  }]
}
```

**Detection regex:** `"Principal"\s*:\s*"\*"[^}]*s3:|s3[^}]*"Principal"\s*:\s*"\*"`
**Severity:** error

### Missing S3 Server-Side Encryption

```hcl
// VULNERABLE: No encryption configuration
resource "aws_s3_bucket" "data" {
  bucket = "sensitive-data-bucket"
}

// SECURE: Server-side encryption with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true
  }
}
```

**Detection guidance:** flag `aws_s3_bucket` resources that do not have a matching `aws_s3_bucket_server_side_encryption_configuration` resource (or equivalent module). Matching `server_side_encryption` inside the bucket block produces false positives because the modern Terraform pattern uses a separate resource (as shown above).
**Severity:** warning

### S3 Public Access Block Not Enabled

```hcl
// VULNERABLE: No public access block — bucket may become public
resource "aws_s3_bucket" "uploads" {
  bucket = "user-uploads"
}

// SECURE: Block all public access
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**Detection regex:** `block_public_acls\s*=\s*false|block_public_policy\s*=\s*false|ignore_public_acls\s*=\s*false|restrict_public_buckets\s*=\s*false`
**Severity:** error

## Lambda: Secrets and Permissions

### Secrets in Lambda Environment Variables

```hcl
// VULNERABLE: Database password in plaintext environment variable
resource "aws_lambda_function" "api" {
  function_name = "api-handler"
  environment {
    variables = {
      DB_PASSWORD = "super-secret-password-123"
      API_KEY     = "AKIAIOSFODNN7EXAMPLE"
    }
  }
}

// SECURE: Reference secrets from Secrets Manager or SSM Parameter Store
resource "aws_lambda_function" "api" {
  function_name = "api-handler"
  environment {
    variables = {
      DB_SECRET_ARN = aws_secretsmanager_secret.db.arn
      API_KEY_PARAM = aws_ssm_parameter.api_key.name
    }
  }
}
```

**Detection regex:** `environment\s*\{[^}]*variables\s*=\s*\{[^}]*(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*"[^"]+"`
**Severity:** error

### Overly Permissive Lambda Execution Role

```hcl
// VULNERABLE: Lambda with AdministratorAccess managed policy
resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

// SECURE: Lambda with specific permissions only
resource "aws_iam_role_policy" "lambda_s3" {
  role   = aws_iam_role.lambda.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::data-bucket/*"
    }]
  })
}
```

**Detection regex:** `policy_arn\s*=\s*"arn:aws:iam::aws:policy/AdministratorAccess"|policy_arn\s*=\s*"arn:aws:iam::aws:policy/PowerUserAccess"`
**Severity:** error

### Lambda Missing VPC Configuration

```hcl
// VULNERABLE: Lambda not in VPC — cannot access private resources, no network isolation
resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  runtime       = "python3.11"
  handler       = "index.handler"
}

// SECURE: Lambda deployed in VPC with specific subnets and security groups
resource "aws_lambda_function" "processor" {
  function_name = "data-processor"
  runtime       = "python3.11"
  handler       = "index.handler"

  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.lambda.id]
  }
}
```

**Detection regex:** `resource\s+"aws_lambda_function"\s+"[^"]+"\s*\{(?![^}]*vpc_config)`
**Severity:** warning

## Security Groups: Open Ingress

### Unrestricted Ingress on Sensitive Ports

```hcl
// VULNERABLE: SSH open to the entire internet
resource "aws_security_group_rule" "ssh_open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}

// SECURE: SSH restricted to bastion or VPN CIDR
resource "aws_security_group_rule" "ssh_vpn" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/24"]
  security_group_id = aws_security_group.web.id
}
```

**Detection regex:** `cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]|CidrIp:\s*["']?0\.0\.0\.0/0`
**Severity:** error

### Security Group Allowing All Traffic

```hcl
// VULNERABLE: All ports open to the internet
resource "aws_security_group_rule" "all_open" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.default.id
}

// SECURE: Only specific ports open, restricted source
resource "aws_security_group_rule" "https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.web.id
}
```

**Detection regex:** `protocol\s*=\s*"-1"[^}]*cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"|from_port\s*=\s*0[^}]*to_port\s*=\s*65535[^}]*"0\.0\.0\.0/0"`
**Severity:** error

### CloudFormation: Open Security Group Ingress

```yaml
# VULNERABLE: SSH open to the world in CloudFormation
Resources:
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0

# SECURE: SSH restricted to VPN range
Resources:
  WebSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 10.0.0.0/24
```

**Detection regex:** `CidrIp:\s*["']?0\.0\.0\.0/0|CidrIpv6:\s*["']?::/0`
**Severity:** error

## KMS: Key Rotation

### Missing KMS Key Rotation

```hcl
// VULNERABLE: KMS key without automatic rotation
resource "aws_kms_key" "data" {
  description = "Encryption key for data"
  enable_key_rotation = false
}

// SECURE: KMS key with automatic rotation enabled
resource "aws_kms_key" "data" {
  description         = "Encryption key for data"
  enable_key_rotation = true
}
```

**Detection regex:** `enable_key_rotation\s*=\s*false`
**Severity:** warning

### KMS Key Missing Rotation Configuration

```hcl
// VULNERABLE: KMS key with no rotation setting at all (defaults to disabled)
resource "aws_kms_key" "app" {
  description = "Application encryption key"
}

// SECURE: Explicitly enable rotation
resource "aws_kms_key" "app" {
  description         = "Application encryption key"
  enable_key_rotation = true
}
```

**Detection regex:** `resource\s+"aws_kms_key"\s+"[^"]+"\s*\{(?![^}]*enable_key_rotation)`
**Severity:** warning

## CloudTrail: Logging and Monitoring

### CloudTrail Disabled or Not Multi-Region

```hcl
// VULNERABLE: CloudTrail only in one region
resource "aws_cloudtrail" "main" {
  name                  = "main-trail"
  s3_bucket_name        = aws_s3_bucket.trail.id
  is_multi_region_trail = false
}

// SECURE: Multi-region trail with log validation
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}
```

**Detection regex:** `is_multi_region_trail\s*=\s*false`
**Severity:** error

### CloudTrail Missing Log Validation

```hcl
// VULNERABLE: No log file validation — tampering undetectable
resource "aws_cloudtrail" "audit" {
  name                       = "audit-trail"
  s3_bucket_name             = aws_s3_bucket.trail.id
  enable_log_file_validation = false
}

// SECURE: Log file validation enabled
resource "aws_cloudtrail" "audit" {
  name                       = "audit-trail"
  s3_bucket_name             = aws_s3_bucket.trail.id
  enable_log_file_validation = true
}
```

**Detection regex:** `enable_log_file_validation\s*=\s*false`
**Severity:** warning

## Secrets Manager: Hardcoded Secrets

### Hardcoded Secrets Instead of Secrets Manager References

```hcl
// VULNERABLE: Hardcoded database credentials in Terraform
resource "aws_db_instance" "main" {
  engine   = "mysql"
  username = "admin"
  password = "MyS3cretP@ss!"
}

// SECURE: Password from Secrets Manager
resource "aws_db_instance" "main" {
  engine   = "mysql"
  username = "admin"
  password = data.aws_secretsmanager_secret_version.db.secret_string
}

data "aws_secretsmanager_secret_version" "db" {
  secret_id = aws_secretsmanager_secret.db.id
}
```

**Detection regex:** `password\s*=\s*"[^"]+"|master_password\s*=\s*"[^"]+"`
**Severity:** error

### Hardcoded Secrets in CloudFormation

```yaml
# VULNERABLE: Hardcoded secret in CloudFormation parameters default
Parameters:
  DBPassword:
    Type: String
    Default: "my-secret-password"

# SECURE: Use AWS Secrets Manager dynamic reference
Resources:
  MyDB:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: '{{resolve:secretsmanager:MySecret:SecretString:password}}'
```

**Detection regex:** `Default:\s*["'][^"']*(?:password|secret|key|token)[^"']*["']`
**Severity:** error

### Secrets in Terraform Variables Default Values

```hcl
// VULNERABLE: Secret with plaintext default value
variable "db_password" {
  type    = string
  default = "admin123"
}

// SECURE: Sensitive variable with no default — must be provided at runtime
variable "db_password" {
  type      = string
  sensitive = true
}
```

**Detection regex:** `variable\s+"[^"]*(?:password|secret|key|token)[^"]*"\s*\{[^}]*default\s*=\s*"[^"]+"`
**Severity:** error

## RDS: Public Access and Encryption

### RDS Instance Publicly Accessible

```hcl
// VULNERABLE: RDS instance publicly accessible
resource "aws_db_instance" "main" {
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true
}

// SECURE: RDS not publicly accessible, in private subnets
resource "aws_db_instance" "main" {
  engine               = "postgres"
  instance_class       = "db.t3.micro"
  publicly_accessible  = false
  db_subnet_group_name = aws_db_subnet_group.private.name
}
```

**Detection regex:** `publicly_accessible\s*=\s*true`
**Severity:** error

### RDS Unencrypted Storage

```hcl
// VULNERABLE: RDS storage not encrypted
resource "aws_db_instance" "main" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  storage_encrypted = false
}

// SECURE: Encrypted storage with KMS key
resource "aws_db_instance" "main" {
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  storage_encrypted = true
  kms_key_id        = aws_kms_key.rds.arn
}
```

**Detection regex:** `storage_encrypted\s*=\s*false`
**Severity:** error

### RDS Missing Deletion Protection

```hcl
// VULNERABLE: No deletion protection on production database
resource "aws_db_instance" "prod" {
  engine                  = "postgres"
  instance_class          = "db.r5.large"
  deletion_protection     = false
}

// SECURE: Deletion protection enabled
resource "aws_db_instance" "prod" {
  engine                  = "postgres"
  instance_class          = "db.r5.large"
  deletion_protection     = true
  backup_retention_period = 7
}
```

**Detection regex:** `deletion_protection\s*=\s*false`
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| IAM wildcard actions (SA-AWS-01) | Critical | Immediate | Medium |
| Missing IAM conditions (SA-AWS-02) | High | 1 week | Low |
| Overly permissive trust policies (SA-AWS-03) | Critical | Immediate | Medium |
| iam:PassRole abuse (SA-AWS-04) | Critical | Immediate | Medium |
| Public S3 bucket (SA-AWS-05) | Critical | Immediate | Low |
| Missing S3 encryption (SA-AWS-06) | High | 1 week | Low |
| Lambda env var secrets (SA-AWS-07) | Critical | Immediate | Medium |
| Overly permissive Lambda role (SA-AWS-08) | High | 1 week | Medium |
| Open security groups (SA-AWS-09) | Critical | Immediate | Low |
| Missing KMS key rotation (SA-AWS-10) | Medium | 1 month | Low |
| CloudTrail misconfiguration (SA-AWS-11) | High | 1 week | Low |
| Hardcoded secrets (SA-AWS-12) | Critical | Immediate | Medium |
| RDS publicly accessible (SA-AWS-13) | Critical | Immediate | Low |
| RDS unencrypted storage (SA-AWS-14) | High | 1 week | Low |
| RDS missing deletion protection (SA-AWS-15) | Medium | 1 month | Low |

## Related References

- `owasp-top10.md` — OWASP Top 10 mapping
- `iac-security.md` — Infrastructure-as-Code security patterns
- `cryptography-guide.md` — Encryption and key management
- `security-logging.md` — Logging and monitoring patterns
- `api-key-encryption.md` — API key and secrets management

## Changelog

| Date | Change | Reason |
|------|--------|--------|
| 2026-03-31 | Initial release | Cloud security references |
