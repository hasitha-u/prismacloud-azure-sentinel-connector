# Generate a random integer to create a globally unique name
resource "random_integer" "ri" {
  min = 10000
  max = 99999
}

resource "time_rotating" "rotation" {
  rotation_rfc3339 = null
  rotation_years   = 2

  triggers = {
    end_date = null
    years    = 1
  }
}

locals {
  appname = "${var.app_prefix}${random_integer.ri.result}"
}

# Create the resource group
resource "azurerm_resource_group" "rg" {
  name     = local.appname
  location = var.location
}

# Create the Linux App Service Plan
resource "azurerm_service_plan" "appserviceplan" {
  name                = local.appname
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_application_insights" "app_insights" {
  application_type    = "web"
  location            = azurerm_resource_group.rg.location
  name                = local.appname
  resource_group_name = azurerm_resource_group.rg.name
  sampling_percentage = 0
}
resource "azurerm_storage_account" "storage_account" {
  account_replication_type = "LRS"
  account_tier             = "Standard"
  location                 = azurerm_resource_group.rg.location
  min_tls_version          = "TLS1_0"
  name                     = local.appname
  resource_group_name      = azurerm_resource_group.rg.name
}

data "archive_file" "file_function_app" {
  type        = "zip"
  source_dir  = "./prisma-cloud-conn-function-app"
  output_path = "prisma-cloud-conn-function-app.zip"
}

resource "azurerm_storage_blob" "storage_blob" {
  name                   = "${filesha256(data.archive_file.file_function_app.output_path)}.zip"
  storage_account_name   = azurerm_storage_account.storage_account.name
  storage_container_name = azurerm_storage_container.functions-package.name
  type                   = "Block"
  source                 = data.archive_file.file_function_app.output_path
}

data "azurerm_storage_account_blob_container_sas" "storage_account_blob_container_sas" {
  connection_string = azurerm_storage_account.storage_account.primary_connection_string
  container_name    = azurerm_storage_container.functions-package.name

  start  = timestamp()
  expiry = time_rotating.rotation.rotation_rfc3339

  permissions {
    read   = true
    add    = false
    create = false
    write  = false
    delete = false
    list   = false
  }
}

resource "azurerm_storage_container" "functions-package" {
  name                 = "functions-package"
  storage_account_name = azurerm_storage_account.storage_account.name
}
resource "azurerm_storage_container" "azure-webjobs-hosts" {
  name                 = "azure-webjobs-hosts"
  storage_account_name = azurerm_storage_account.storage_account.name
}
resource "azurerm_storage_container" "azure-webjobs-secrets" {
  name                 = "azure-webjobs-secrets"
  storage_account_name = azurerm_storage_account.storage_account.name
}
resource "azurerm_storage_container" "scm-releases" {
  name                 = "scm-releases"
  storage_account_name = azurerm_storage_account.storage_account.name
}
resource "azurerm_storage_share" "prismacloudcheckpoint" {
  name                 = "prismacloudcheckpoint"
  quota                = 5120
  storage_account_name = azurerm_storage_account.storage_account.name
}

resource "azurerm_linux_function_app" "function_app" {
  app_settings = {
    AzureSentinelSharedKey   = var.azure_sentinel_shared_key
    AzureSentinelWorkspaceId = var.azure_sentinel_workspace_id
    LogType                  = var.log_type
    PrismaCloudAPIUrl        = var.prisma_cloud_api_url
    PrismaCloudAccessKeyID   = var.prisma_cloud_access_key_id
    PrismaCloudSecretKey     = var.prisma_cloud_access_secret_key
    logAnalyticsUri          = "https://${var.azure_sentinel_workspace_id}.ods.opinsights.azure.com"
    WEBSITE_RUN_FROM_PACKAGE = "https://${azurerm_storage_account.storage_account.name}.blob.core.windows.net/${azurerm_storage_container.functions-package.name}/${azurerm_storage_blob.storage_blob.name}${data.azurerm_storage_account_blob_container_sas.storage_account_blob_container_sas.sas}"
  }

  builtin_logging_enabled     = false
  client_certificate_mode     = "Required"
  https_only                  = true
  location                    = azurerm_resource_group.rg.location
  name                        = local.appname
  resource_group_name         = azurerm_resource_group.rg.name
  service_plan_id             = azurerm_service_plan.appserviceplan.id
  storage_account_name        = azurerm_storage_account.storage_account.name
  storage_account_access_key  = azurerm_storage_account.storage_account.primary_access_key
  functions_extension_version = "~4"

  tags = {
    "hidden-link: /app-insights-conn-string"         = azurerm_application_insights.app_insights.connection_string
    "hidden-link: /app-insights-instrumentation-key" = azurerm_application_insights.app_insights.instrumentation_key
    "hidden-link: /app-insights-resource-id"         = azurerm_application_insights.app_insights.id
  }

  identity {
    type = "SystemAssigned"
  }
  site_config {
    application_stack {
      python_version = "3.8"
    }
    application_insights_connection_string = azurerm_application_insights.app_insights.connection_string
    application_insights_key               = azurerm_application_insights.app_insights.instrumentation_key
  }
}

resource "azurerm_monitor_action_group" "action_group" {
  name                = "Smart detector Action Group - ${local.appname}"
  resource_group_name = azurerm_resource_group.rg.name
  short_name          = "action-group"

  dynamic "email_receiver" {
    for_each = var.failure_notification_emails
    content {
      name          = email_receiver.value["name"]
      email_address = email_receiver.value["email"]
    }
  }
}

resource "azurerm_monitor_smart_detector_alert_rule" "smart_detector_alert_rule" {
  description         = "Failure Anomalies notifies you of an unusual rise in the rate of failed HTTP requests or dependency calls."
  detector_type       = "FailureAnomaliesDetector"
  frequency           = "PT1M"
  name                = "Failure Anomalies - ${local.appname}"
  resource_group_name = azurerm_resource_group.rg.name
  scope_resource_ids  = [azurerm_application_insights.app_insights.id]
  severity            = "Sev3"
  action_group {
    ids = [azurerm_monitor_action_group.action_group.id]
  }
}

