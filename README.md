# Prisma Cloud to Azure Sentinel Connector

This project provides a Terraform-based solution to deploy an Azure Function App that integrates Prisma Cloud CSPM and Compute alerts into Microsoft Sentinel.

## Overview

The solution uses an Azure Function, written in Python, to fetch alerts from Prisma Cloud Compute and ingest them into an Azure Log Analytics Workspace that is connected to Microsoft Sentinel.

## Prerequisites

- **Azure Subscription** with permission to deploy resources.
- **Microsoft Sentinel** enabled in a Log Analytics Workspace.
- **Prisma Cloud Compute** access and credentials.
- **Terraform** installed locally.
- **Azure CLI** authenticated with your subscription.

## Deployment Steps

1. **Clone the Repository**:

    ```bash
    git clone https://github.com/hasitha-u/prismacloud-azure-sentinel-connector.git
    cd prismacloud-azure-sentinel-connector
    ```

2. **Set Required Variables** in `terraform.tfvars` or define them during apply:
    - `location`
    - `function_app_name`
    - `resource_group_name`
    - `workspace_id`
    - `prisma_cloud_api_url`
    - `prisma_cloud_access_key`
    - `prisma_cloud_secret_key`

3. **Initialize Terraform**:

    ```bash
    terraform init
    ```

4. **Apply Terraform Configuration**:

    ```bash
    terraform apply
    ```

    Confirm the prompt to deploy the function and supporting resources.

## Function Details

The function is located in the `prisma-cloud-conn-function-app/` directory and is structured to:

- Use HTTP Trigger (for manual execution).
- Authenticate using Prisma Cloud Compute API credentials.
- Pull alerts and send them to Azure Sentinel using the Data Collector API.

Environment variables are passed during deployment from Terraform.

## Logs and Monitoring

Monitor the Azure Function App logs to verify the alerts are being sent to Sentinel:

- Azure Portal > Function App > Logs
- Log Analytics Workspace > Run queries like:

    ```kusto
    AzureDiagnostics
    | where ResourceType == "FUNCTIONS"
    ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
