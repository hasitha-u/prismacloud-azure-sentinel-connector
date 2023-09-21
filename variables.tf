variable "app_prefix" {
  description = "App Name Prefix"
  type        = string
  default     = "prismacloudconn"
}

variable "location" {
  description = "Azure location"
  type        = string
  default     = "uksouth"
}

variable "azure_sentinel_shared_key" {
  description = "AzureSentinelSharedKey"
  type        = string
}

variable "azure_sentinel_workspace_id" {
  description = "AzureSentinelWorkspaceId"
  type        = string
}

variable "log_type" {
  description = "LogType"
  type        = string
  default     = "alert, audit"
}

variable "prisma_cloud_api_url" {
  description = "prisma_cloud_api_url"
  type        = string
}

variable "prisma_cloud_access_key_id" {
  description = "prisma_cloud_access_key_id"
  type        = string
  sensitive   = true
}

variable "prisma_cloud_access_secret_key" {
  description = "prisma_cloud_access_secret_key"
  type        = string
  sensitive   = true
}

variable "failure_notification_emails" {
  description = <<-EOF
  List of names and email addresses for failure notificaitons
  - `name`    - (required|string) Name.
  - `email`   - (required|string) Email address.

  Example:
  ```
  [
    {
      name  = "John Smith"
      email = "jsmith@example.com"
    },
    {
      name  = "Jane Doe"
      email = "jdoe@example.com"
    },
  ]
  ```
  EOF
  type        = any
  default     = []
}