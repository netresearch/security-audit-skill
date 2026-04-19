# Azure Security Patterns

Security patterns, common misconfigurations, and detection regexes for Microsoft Azure infrastructure. Covers RBAC, Blob Storage, Azure Functions, NSGs, Key Vault, and Activity Log across Bicep, ARM templates, and Terraform configurations.

## RBAC: Overly Permissive Role Assignments

### Owner/Contributor at Subscription Scope

```hcl
// VULNERABLE: Owner role at subscription scope
resource "azurerm_role_assignment" "owner" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Owner"
  principal_id         = var.user_object_id
}

// SECURE: Specific role at resource group scope
resource "azurerm_role_assignment" "contributor" {
  scope                = azurerm_resource_group.app.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = var.user_object_id
}
```

**Detection regex:** `role_definition_name\s*=\s*"(Owner|Contributor)"[^}]*subscription|subscription[^}]*role_definition_name\s*=\s*"(Owner|Contributor)"`
**Severity:** error

### Bicep: Owner Role Assignment at Subscription

```bicep
// VULNERABLE: Owner at subscription scope
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, principalId, ownerRoleId)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8e3af657-a8ff-443c-a75c-2fe8c4bcb635')
    principalId: principalId
  }
}

// SECURE: Scoped to resource group with specific role
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, principalId, readerRoleId)
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
    principalId: principalId
    description: 'Reader access for monitoring'
  }
}
```

**Detection regex:** `8e3af657-a8ff-443c-a75c-2fe8c4bcb635|b24988ac-6180-42a0-ab88-20f7382dd24c`
**Severity:** error

### Missing Conditions on Role Assignments

```hcl
// VULNERABLE: Role assignment without conditions
resource "azurerm_role_assignment" "storage" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = var.app_principal_id
}

// SECURE: Role assignment with condition
resource "azurerm_role_assignment" "storage" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Owner"
  principal_id         = var.app_principal_id
  condition            = "((!(ActionMatches{'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete'}))"
  condition_version    = "2.0"
}
```

**Detection regex:** `role_definition_name\s*=\s*"Storage Blob Data Owner"(?![^}]*condition\s*=)`
**Severity:** warning

## Blob Storage: Public Access and Encryption

### Public Access Enabled on Storage Account

```hcl
// VULNERABLE: Public blob access enabled
resource "azurerm_storage_account" "main" {
  name                     = "storageaccount"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = true
}

// SECURE: Public access disabled
resource "azurerm_storage_account" "main" {
  name                     = "storageaccount"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = false
  min_tls_version          = "TLS1_2"
}
```

**Detection regex:** `allow_nested_items_to_be_public\s*=\s*true|allow_blob_public_access\s*=\s*true`
**Severity:** error

### Bicep: Public Blob Access

```bicep
// VULNERABLE: Public access allowed
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: true
  }
}

// SECURE: Public access disabled with minimum TLS
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}
```

**Detection regex:** `allowBlobPublicAccess:\s*true|"allowBlobPublicAccess"\s*:\s*true`
**Severity:** error

### Anonymous Access on Blob Container

```hcl
// VULNERABLE: Container with anonymous blob access
resource "azurerm_storage_container" "uploads" {
  name                  = "uploads"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "blob"
}

// SECURE: Container with private access
resource "azurerm_storage_container" "uploads" {
  name                  = "uploads"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}
```

**Detection regex:** `container_access_type\s*=\s*"(blob|container)"`
**Severity:** error

### Missing Customer-Managed Encryption

```hcl
// VULNERABLE: Using default Microsoft-managed keys
resource "azurerm_storage_account" "data" {
  name                     = "datastore"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

// SECURE: Customer-managed encryption key
resource "azurerm_storage_account" "data" {
  name                     = "datastore"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.storage.id
    user_assigned_identity_id = azurerm_user_assigned_identity.storage.id
  }
}
```

**Detection regex:** `resource\s+"azurerm_storage_account"\s+"[^"]+"\s*\{(?![^}]*customer_managed_key)`
**Severity:** warning

## Azure Functions: Authentication and Secrets

### Anonymous Authentication Level

```hcl
// VULNERABLE: Function with anonymous auth level
resource "azurerm_function_app_function" "api" {
  name            = "api-handler"
  function_app_id = azurerm_linux_function_app.main.id
  config_json = jsonencode({
    bindings = [{
      authLevel = "anonymous"
      type      = "httpTrigger"
      direction = "in"
      name      = "req"
      methods   = ["get", "post"]
    }]
  })
}

// SECURE: Function-level key required
resource "azurerm_function_app_function" "api" {
  name            = "api-handler"
  function_app_id = azurerm_linux_function_app.main.id
  config_json = jsonencode({
    bindings = [{
      authLevel = "function"
      type      = "httpTrigger"
      direction = "in"
      name      = "req"
      methods   = ["get", "post"]
    }]
  })
}
```

**Detection regex:** `authLevel["\s]*[:=]\s*["']?anonymous|"authLevel"\s*:\s*"anonymous"`
**Severity:** error

### Secrets in App Settings

```hcl
// VULNERABLE: Connection string hardcoded in app settings
resource "azurerm_linux_function_app" "main" {
  name                = "my-func-app"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "eastus"
  service_plan_id     = azurerm_service_plan.plan.id

  app_settings = {
    DB_CONNECTION = "Server=tcp:myserver.database.windows.net;Database=mydb;User ID=admin;Password=Secret123!"
    API_SECRET    = "sk-live-abc123def456"
  }
}

// SECURE: Reference Key Vault secrets
resource "azurerm_linux_function_app" "main" {
  name                = "my-func-app"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "eastus"
  service_plan_id     = azurerm_service_plan.plan.id

  app_settings = {
    DB_CONNECTION = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.db_conn.id})"
    API_SECRET    = "@Microsoft.KeyVault(SecretUri=${azurerm_key_vault_secret.api.id})"
  }
}
```

**Detection regex:** `app_settings\s*=\s*\{[^}]*(PASSWORD|SECRET|KEY|TOKEN|CONNECTION)\s*=\s*"(?!@Microsoft\.KeyVault)[^"]+"`
**Severity:** error

## NSGs: Open Inbound Rules

### Unrestricted Inbound on Sensitive Ports

```hcl
// VULNERABLE: SSH open to the entire internet
resource "azurerm_network_security_rule" "ssh_open" {
  name                        = "allow-ssh"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}

// SECURE: SSH restricted to VPN CIDR
resource "azurerm_network_security_rule" "ssh_vpn" {
  name                        = "allow-ssh-vpn"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  destination_port_range      = "22"
  source_address_prefix       = "10.0.0.0/24"
  destination_address_prefix  = "10.0.1.0/24"
  resource_group_name         = azurerm_resource_group.rg.name
  network_security_group_name = azurerm_network_security_group.nsg.name
}
```

**Detection regex:** `source_address_prefix\s*=\s*"\*"[^}]*direction\s*=\s*"Inbound"|direction\s*=\s*"Inbound"[^}]*source_address_prefix\s*=\s*"\*"`
**Severity:** error

### Bicep: Open NSG Inbound Rule

```bicep
// VULNERABLE: RDP open to internet
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'web-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-rdp'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          destinationPortRange: '3389'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

// SECURE: RDP restricted to Azure Bastion subnet
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'web-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-rdp-bastion'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          destinationPortRange: '3389'
          sourceAddressPrefix: 'AzureBastionSubnet'
          destinationAddressPrefix: 'VirtualNetwork'
        }
      }
    ]
  }
}
```

**Detection regex:** `sourceAddressPrefix['"]*\s*[:=]\s*['"]\*['"]|"sourceAddressPrefix"\s*:\s*"\*"`
**Severity:** error

## Key Vault: Soft Delete and Access

### Missing Soft Delete on Key Vault

```hcl
// VULNERABLE: Soft delete not explicitly enabled (older API versions)
resource "azurerm_key_vault" "main" {
  name                = "my-key-vault"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
}

// SECURE: Soft delete with purge protection
resource "azurerm_key_vault" "main" {
  name                = "my-key-vault"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true
}
```

**Detection regex:** `purge_protection_enabled\s*=\s*false`
**Severity:** error

### Key Vault Using Access Policies Instead of RBAC

```hcl
// VULNERABLE: Access policies (legacy, harder to audit)
resource "azurerm_key_vault" "main" {
  name                = "my-key-vault"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.rg.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = var.user_object_id
    secret_permissions = ["Get", "List", "Set", "Delete"]
    key_permissions    = ["Get", "List", "Create", "Delete"]
  }
}

// SECURE: RBAC-based access control
resource "azurerm_key_vault" "main" {
  name                       = "my-key-vault"
  location                   = "eastus"
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90
}
```

**Detection regex:** `enable_rbac_authorization\s*=\s*false|access_policy\s*\{`
**Severity:** warning

### Bicep: Key Vault Without Purge Protection

```bicep
// VULNERABLE: No purge protection
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'my-key-vault'
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enablePurgeProtection: false
  }
}

// SECURE: Purge protection and RBAC enabled
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'my-key-vault'
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enablePurgeProtection: true
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
  }
}
```

**Detection regex:** `enablePurgeProtection:\s*false|"enablePurgeProtection"\s*:\s*false`
**Severity:** error

## Activity Log: Diagnostic Settings

### Missing Diagnostic Settings

```hcl
// VULNERABLE: No diagnostic settings for activity log
// (absence of azurerm_monitor_diagnostic_setting)

// SECURE: Activity log forwarded to Log Analytics
resource "azurerm_monitor_diagnostic_setting" "activity_log" {
  name                       = "activity-log-analytics"
  target_resource_id         = data.azurerm_subscription.primary.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "Administrative"
  }
  enabled_log {
    category = "Security"
  }
  enabled_log {
    category = "Alert"
  }
  enabled_log {
    category = "Policy"
  }
}
```

**Detection guidance:** flag activity-log-capable resources that lack a companion `azurerm_monitor_diagnostic_setting`. Matching `azurerm_monitor_diagnostic_setting` directly would flag the secure pattern shown above — use absence-of-resource checks (e.g., Checkov, tfsec, or a module inventory) instead of a simple regex.
**Severity:** warning

### Bicep: Missing Diagnostic Settings

```bicep
// VULNERABLE: No diagnostic settings configured

// SECURE: Activity log diagnostic setting
resource diagnosticSetting 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'activity-log-analytics'
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      { category: 'Administrative', enabled: true }
      { category: 'Security', enabled: true }
      { category: 'Alert', enabled: true }
    ]
  }
}
```

**Detection guidance:** flag Bicep/ARM deployments without a `Microsoft.Insights/diagnosticSettings` resource covering the target scope. Matching the resource type directly flags the secure pattern — prefer an absence-of-resource check.
**Severity:** warning

## Azure SQL: Public Access

### Azure SQL Public Network Access

```hcl
// VULNERABLE: Public network access enabled
resource "azurerm_mssql_server" "main" {
  name                         = "sql-server"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = "eastus"
  version                      = "12.0"
  public_network_access_enabled = true
}

// SECURE: Public access disabled, private endpoint
resource "azurerm_mssql_server" "main" {
  name                         = "sql-server"
  resource_group_name          = azurerm_resource_group.rg.name
  location                     = "eastus"
  version                      = "12.0"
  public_network_access_enabled = false
}
```

**Detection regex:** `public_network_access_enabled\s*=\s*true`
**Severity:** error

### Azure SQL Firewall Allow All Azure IPs

```hcl
// VULNERABLE: Allow all Azure services (0.0.0.0 rule)
resource "azurerm_mssql_firewall_rule" "allow_azure" {
  name             = "AllowAllAzureIps"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

// SECURE: Use private endpoints instead of firewall rules
resource "azurerm_private_endpoint" "sql" {
  name                = "sql-private-endpoint"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.rg.name
  subnet_id           = azurerm_subnet.private.id

  private_service_connection {
    name                           = "sql-connection"
    private_connection_resource_id = azurerm_mssql_server.main.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }
}
```

**Detection regex:** `start_ip_address\s*=\s*"0\.0\.0\.0"[^}]*end_ip_address\s*=\s*"0\.0\.0\.0"`
**Severity:** warning

### Missing TDE on Azure SQL

```hcl
// VULNERABLE: Transparent Data Encryption not configured with CMK
resource "azurerm_mssql_database" "main" {
  name      = "my-database"
  server_id = azurerm_mssql_server.main.id
}

// SECURE: TDE with customer-managed key
resource "azurerm_mssql_server_transparent_data_encryption" "main" {
  server_id        = azurerm_mssql_server.main.id
  key_vault_key_id = azurerm_key_vault_key.sql_tde.id
}
```

**Detection guidance:** flag `azurerm_mssql_server` resources that lack a matching `azurerm_mssql_server_transparent_data_encryption`. A nested-block regex produces false positives because TDE lives in a separate resource in modern Terraform.
**Severity:** warning

### Azure SQL Auditing Not Enabled

```hcl
// VULNERABLE: No auditing configured
resource "azurerm_mssql_server" "main" {
  name                = "sql-server"
  resource_group_name = azurerm_resource_group.rg.name
  location            = "eastus"
  version             = "12.0"
}

// SECURE: Extended auditing enabled
resource "azurerm_mssql_server_extended_auditing_policy" "main" {
  server_id              = azurerm_mssql_server.main.id
  storage_endpoint       = azurerm_storage_account.audit.primary_blob_endpoint
  retention_in_days      = 90
  log_monitoring_enabled = true
}
```

**Detection guidance:** flag `azurerm_mssql_server` resources without a matching `azurerm_mssql_server_extended_auditing_policy`. Matching the auditing-policy resource type directly flags the secure pattern.
**Severity:** warning

## Remediation Priority

| Finding | Severity | Remediation Timeline | Effort |
|---------|----------|---------------------|--------|
| Owner/Contributor at subscription (SA-AZURE-01) | Critical | Immediate | Medium |
| Missing RBAC conditions (SA-AZURE-02) | High | 1 week | Low |
| Public blob access (SA-AZURE-03) | Critical | Immediate | Low |
| Missing CMK encryption (SA-AZURE-04) | Medium | 1 month | Medium |
| Anonymous function auth (SA-AZURE-05) | Critical | Immediate | Low |
| Open NSG inbound rules (SA-AZURE-06) | Critical | Immediate | Low |
| Missing purge protection (SA-AZURE-07) | High | 1 week | Low |
| Key Vault access policies (SA-AZURE-08) | Medium | 1 month | Medium |
| Missing diagnostic settings (SA-AZURE-09) | High | 1 week | Low |
| SQL public network access (SA-AZURE-10) | Critical | Immediate | Medium |
| SQL missing TDE (SA-AZURE-11) | Medium | 1 month | Medium |
| SQL auditing not enabled (SA-AZURE-12) | High | 1 week | Low |

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
