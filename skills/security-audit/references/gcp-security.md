# GCP Security Patterns

Security patterns, common misconfigurations, and detection regexes for Google Cloud Platform infrastructure. Covers IAM, Cloud Storage, Cloud Functions, VPC Firewall, KMS, and Audit Logs across Terraform, JSON, and YAML configurations.

## IAM: Primitive Roles and Service Accounts

### Primitive Roles on Projects (Owner/Editor)

```hcl
// VULNERABLE: Granting Owner role at project level
resource "google_project_iam_member" "admin" {
  project = "my-project"
  role    = "roles/owner"
  member  = "user:admin@example.com"
}

// SECURE: Granular predefined role scoped to specific service
resource "google_project_iam_member" "storage_admin" {
  project = "my-project"
  role    = "roles/storage.admin"
  member  = "user:admin@example.com"
}
```

**Detection regex:** `role\s*=\s*"roles/(owner|editor)"|"roles/(owner|editor)"`
**Severity:** error

### Service Account Key Files

```hcl
// VULNERABLE: Creating downloadable service account keys
resource "google_service_account_key" "sa_key" {
  service_account_id = google_service_account.mysa.name
}

// SECURE: Use Workload Identity Federation instead of key files
resource "google_iam_workload_identity_pool" "pool" {
  workload_identity_pool_id = "github-pool"
  display_name              = "GitHub Actions Pool"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
```

**Detection regex:** `resource\s+"google_service_account_key"|google_service_account_key\s*\{`
**Severity:** error

### allUsers / allAuthenticatedUsers Bindings

```hcl
// VULNERABLE: IAM binding grants access to all internet users
resource "google_project_iam_binding" "public" {
  project = "my-project"
  role    = "roles/viewer"
  members = ["allUsers"]
}

// SECURE: Binding restricted to specific group
resource "google_project_iam_binding" "team" {
  project = "my-project"
  role    = "roles/viewer"
  members = ["group:team@example.com"]
}
```

**Detection regex:** `"allUsers"|"allAuthenticatedUsers"|member\s*=\s*"allUsers"|member\s*=\s*"allAuthenticatedUsers"`
**Severity:** error

### Overly Broad Service Account Impersonation

```hcl
// VULNERABLE: Any user can impersonate any service account
resource "google_project_iam_member" "sa_token_creator" {
  project = "my-project"
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "user:developer@example.com"
}

// SECURE: Impersonation scoped to specific service account
resource "google_service_account_iam_member" "sa_token_creator" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:ci@my-project.iam.gserviceaccount.com"
}
```

**Detection regex:** `role\s*=\s*"roles/iam\.serviceAccountTokenCreator"[^}]*google_project_iam|google_project_iam[^}]*serviceAccountTokenCreator`
**Severity:** warning

## Cloud Storage: Public Access and Encryption

### Public Storage Bucket ACL

```hcl
// VULNERABLE: Cloud Storage bucket accessible to allUsers
resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}

// SECURE: Access restricted to specific service account
resource "google_storage_bucket_iam_member" "app" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:app@my-project.iam.gserviceaccount.com"
}
```

**Detection regex:** `google_storage_bucket_iam[^}]*(allUsers|allAuthenticatedUsers)`
**Severity:** error

### Missing Customer-Managed Encryption Key (CMEK)

```hcl
// VULNERABLE: Bucket using default Google-managed encryption
resource "google_storage_bucket" "sensitive" {
  name     = "sensitive-data"
  location = "US"
}

// SECURE: Bucket using customer-managed encryption key
resource "google_storage_bucket" "sensitive" {
  name     = "sensitive-data"
  location = "US"
  encryption {
    default_kms_key_name = google_kms_crypto_key.storage.id
  }
}
```

**Detection regex:** `resource\s+"google_storage_bucket"\s+"[^"]+"\s*\{(?![^}]*encryption\s*\{)`
**Severity:** warning

### Uniform Bucket-Level Access Not Enabled

```hcl
// VULNERABLE: Object-level ACLs allowed — inconsistent access control
resource "google_storage_bucket" "data" {
  name                        = "my-data"
  location                    = "US"
  uniform_bucket_level_access = false
}

// SECURE: Uniform bucket-level access enforced
resource "google_storage_bucket" "data" {
  name                        = "my-data"
  location                    = "US"
  uniform_bucket_level_access = true
}
```

**Detection regex:** `uniform_bucket_level_access\s*=\s*false`
**Severity:** warning

### Public Bucket in YAML/JSON Configuration

```yaml
# VULNERABLE: Public predefinedAcl in deployment config
resources:
  - name: data-bucket
    type: storage.v1.bucket
    properties:
      predefinedAcl: publicRead
      location: US

# SECURE: Private access
resources:
  - name: data-bucket
    type: storage.v1.bucket
    properties:
      predefinedAcl: private
      location: US
      iamConfiguration:
        uniformBucketLevelAccess:
          enabled: true
```

**Detection regex:** `predefinedAcl:\s*public|predefinedAcl:\s*["']public`
**Severity:** error

## Cloud Functions: Secrets and Access

### Secrets in Cloud Functions Environment Variables

```hcl
// VULNERABLE: Secret in plaintext environment variable
resource "google_cloudfunctions_function" "api" {
  name    = "api-handler"
  runtime = "nodejs18"
  environment_variables = {
    DB_PASSWORD = "s3cret-pass!"
    API_KEY     = "AIzaSyB_example_key"
  }
}

// SECURE: Reference secrets from Secret Manager
resource "google_cloudfunctions_function" "api" {
  name    = "api-handler"
  runtime = "nodejs18"
  secret_environment_variables {
    key        = "DB_PASSWORD"
    project_id = "my-project"
    secret     = google_secret_manager_secret.db_pass.secret_id
    version    = "latest"
  }
}
```

**Detection regex:** `environment_variables\s*=\s*\{[^}]*(PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=\s*"[^"]+"`
**Severity:** error

### allUsers Cloud Functions Invoker

```hcl
// VULNERABLE: Function invocable by anyone on the internet
resource "google_cloudfunctions_function_iam_member" "public" {
  cloud_function = google_cloudfunctions_function.api.name
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}

// SECURE: Function invocable only by specific service account
resource "google_cloudfunctions_function_iam_member" "invoker" {
  cloud_function = google_cloudfunctions_function.api.name
  role           = "roles/cloudfunctions.invoker"
  member         = "serviceAccount:scheduler@my-project.iam.gserviceaccount.com"
}
```

**Detection regex:** `cloudfunctions\.invoker[^}]*allUsers|allUsers[^}]*cloudfunctions\.invoker`
**Severity:** error

### Cloud Functions Missing VPC Connector

```hcl
// VULNERABLE: Function without VPC connector — no private network access
resource "google_cloudfunctions_function" "processor" {
  name    = "data-processor"
  runtime = "python311"
}

// SECURE: Function with VPC connector for private network access
resource "google_cloudfunctions_function" "processor" {
  name                  = "data-processor"
  runtime               = "python311"
  vpc_connector         = google_vpc_access_connector.connector.id
  vpc_connector_egress_settings = "ALL_TRAFFIC"
}
```

**Detection regex:** `resource\s+"google_cloudfunctions_function"\s+"[^"]+"\s*\{(?![^}]*vpc_connector)`
**Severity:** warning

## VPC Firewall: Open Ingress

### Unrestricted Ingress Rules

```hcl
// VULNERABLE: Firewall rule allows SSH from anywhere
resource "google_compute_firewall" "ssh_open" {
  name    = "allow-ssh"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

// SECURE: SSH restricted to IAP tunnel range
resource "google_compute_firewall" "ssh_iap" {
  name    = "allow-ssh-iap"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
}
```

**Detection regex:** `source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]`
**Severity:** error

### Firewall Rule Allowing All Protocols

```hcl
// VULNERABLE: All traffic from any source
resource "google_compute_firewall" "allow_all" {
  name    = "allow-all"
  network = google_compute_network.vpc.name

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

// SECURE: Only specific protocols and ports
resource "google_compute_firewall" "web" {
  name    = "allow-web"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.0.0.0/8"]
}
```

**Detection regex:** `protocol\s*=\s*"all"[^}]*source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"`
**Severity:** error

### YAML Firewall Configuration Open to Internet

```yaml
# VULNERABLE: Deployment Manager firewall rule open to all
resources:
  - name: allow-ssh
    type: compute.v1.firewall
    properties:
      network: global/networks/default
      sourceRanges:
        - "0.0.0.0/0"
      allowed:
        - IPProtocol: tcp
          ports:
            - "22"

# SECURE: Restricted source range
resources:
  - name: allow-ssh-internal
    type: compute.v1.firewall
    properties:
      network: global/networks/default
      sourceRanges:
        - "10.128.0.0/9"
      allowed:
        - IPProtocol: tcp
          ports:
            - "22"
```

**Detection regex:** `sourceRanges:[^}]*0\.0\.0\.0/0`
**Severity:** error

## KMS: Key Rotation and Access

### Missing KMS Key Rotation

```hcl
// VULNERABLE: Crypto key without rotation period
resource "google_kms_crypto_key" "data" {
  name     = "data-key"
  key_ring = google_kms_key_ring.ring.id
}

// SECURE: Crypto key with 90-day rotation
resource "google_kms_crypto_key" "data" {
  name            = "data-key"
  key_ring        = google_kms_key_ring.ring.id
  rotation_period = "7776000s"
}
```

**Detection regex:** `resource\s+"google_kms_crypto_key"\s+"[^"]+"\s*\{(?![^}]*rotation_period)`
**Severity:** warning

### Overly Permissive IAM on KMS Keys

```hcl
// VULNERABLE: allUsers can decrypt with this key
resource "google_kms_crypto_key_iam_member" "public_decrypt" {
  crypto_key_id = google_kms_crypto_key.data.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "allUsers"
}

// SECURE: Only specific service account can decrypt
resource "google_kms_crypto_key_iam_member" "decrypt" {
  crypto_key_id = google_kms_crypto_key.data.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:app@my-project.iam.gserviceaccount.com"
}
```

**Detection regex:** `google_kms_crypto_key_iam[^}]*(allUsers|allAuthenticatedUsers)`
**Severity:** error

### KMS Key Destroy Scheduled Duration Too Short

```hcl
// VULNERABLE: Key can be destroyed with only 1 day wait
resource "google_kms_crypto_key" "data" {
  name                       = "data-key"
  key_ring                   = google_kms_key_ring.ring.id
  destroy_scheduled_duration = "86400s"
}

// SECURE: 30-day scheduled destruction duration
resource "google_kms_crypto_key" "data" {
  name                       = "data-key"
  key_ring                   = google_kms_key_ring.ring.id
  destroy_scheduled_duration = "2592000s"
  rotation_period            = "7776000s"
}
```

**Detection regex:** `destroy_scheduled_duration\s*=\s*"86400s"`
**Severity:** warning

## Audit Logs: Data Access Logging

### Data Access Logging Disabled

```hcl
// VULNERABLE: Data access audit logging not configured
resource "google_project_iam_audit_config" "minimal" {
  project = "my-project"
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
}

// SECURE: Full data access audit logging enabled
resource "google_project_iam_audit_config" "full" {
  project = "my-project"
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
```

**Detection regex:** `google_project_iam_audit_config[^}]*ADMIN_READ(?![^}]*(DATA_READ|DATA_WRITE))`
**Severity:** warning

### Missing Audit Config for Critical Services

```hcl
// VULNERABLE: No audit logging configured at all
// (absence of google_project_iam_audit_config resource)

// SECURE: Audit logging for all services
resource "google_project_iam_audit_config" "all_services" {
  project = "my-project"
  service = "allServices"
  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
```

**Detection guidance:** flag GCP projects that lack a `google_project_iam_audit_config` covering `allServices`/`DATA_READ`/`DATA_WRITE`. Matching the resource type directly flags the secure pattern — prefer an absence-of-resource check.
**Severity:** warning

### Audit Log Exemptions for Users

```hcl
// VULNERABLE: Exempting users from audit logging
resource "google_project_iam_audit_config" "exempted" {
  project = "my-project"
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
    exempted_members = [
      "user:admin@example.com",
    ]
  }
}

// SECURE: No exemptions — all access is logged
resource "google_project_iam_audit_config" "full" {
  project = "my-project"
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
  }
}
```

**Detection regex:** `exempted_members\s*=\s*\[`
**Severity:** warning

## Cloud SQL: Public Access

### Cloud SQL Public IP

```hcl
// VULNERABLE: Cloud SQL with public IP enabled
resource "google_sql_database_instance" "main" {
  name             = "main-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks {
        value = "0.0.0.0/0"
        name  = "all"
      }
    }
  }
}

// SECURE: Private IP only, accessed via Cloud SQL Proxy
resource "google_sql_database_instance" "main" {
  name             = "main-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}
```

**Detection regex:** `authorized_networks[^}]*0\.0\.0\.0/0|ipv4_enabled\s*=\s*true`
**Severity:** error

### Cloud SQL Missing Encryption

```hcl
// VULNERABLE: Database without CMEK encryption
resource "google_sql_database_instance" "main" {
  name             = "main-db"
  database_version = "MYSQL_8_0"
  settings {
    tier = "db-f1-micro"
  }
}

// SECURE: Database with CMEK
resource "google_sql_database_instance" "main" {
  name               = "main-db"
  database_version   = "MYSQL_8_0"
  encryption_key_name = google_kms_crypto_key.sql.id
  settings {
    tier = "db-f1-micro"
  }
}
```

**Detection regex:** `resource\s+"google_sql_database_instance"\s+"[^"]+"\s*\{(?![^}]*encryption_key_name)`
**Severity:** warning

### Cloud SQL Backup Not Enabled

```hcl
// VULNERABLE: Backups not enabled
resource "google_sql_database_instance" "main" {
  name             = "main-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = false
    }
  }
}

// SECURE: Automated backups with PITR
resource "google_sql_database_instance" "main" {
  name             = "main-db"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }
}
```

**Detection regex:** `backup_configuration\s*\{[^}]*enabled\s*=\s*false`
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| Primitive roles on projects (SA-GCP-01) | Critical | Immediate | Medium |
| Service account key files (SA-GCP-02) | High | 1 week | High |
| allUsers/allAuthenticatedUsers (SA-GCP-03) | Critical | Immediate | Low |
| Public storage bucket (SA-GCP-04) | Critical | Immediate | Low |
| Missing CMEK on storage (SA-GCP-05) | Medium | 1 month | Medium |
| Cloud Functions env secrets (SA-GCP-06) | Critical | Immediate | Medium |
| Public Cloud Functions invoker (SA-GCP-07) | Critical | Immediate | Low |
| Open VPC firewall rules (SA-GCP-08) | Critical | Immediate | Low |
| Missing KMS key rotation (SA-GCP-09) | Medium | 1 month | Low |
| Audit logging gaps (SA-GCP-10) | High | 1 week | Low |
| Cloud SQL public access (SA-GCP-11) | Critical | Immediate | Medium |
| Cloud SQL backup disabled (SA-GCP-12) | High | 1 week | Low |

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
