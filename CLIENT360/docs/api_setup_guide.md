# Optional API Setup Guide

The project runs with sample data by default. API setup is optional.

## Microsoft 365 / Microsoft Graph

Create a Microsoft Entra ID app registration and store values in `.env`:

```text
MS_TENANT_ID=...
MS_CLIENT_ID=...
MS_CLIENT_SECRET=...
```

Suggested read-focused permissions for a controlled test tenant:

- `User.Read.All`
- `Reports.Read.All`
- `UserAuthenticationMethod.Read.All`

Admin consent is usually required for tenant-wide reporting/security data.

## Azure

Install Azure CLI and sign in:

```bash
az login
az account set --subscription "YOUR_SUBSCRIPTION_NAME_OR_ID"
```

Useful export commands:

```bash
az vm list --show-details --output json > data/sample/azure_vms.json
az network nsg rule list --resource-group MyResourceGroup --nsg-name MyNsg --output json > data/sample/azure_nsg_rules.json
```

## AWS

Create or use an IAM identity with read-only EC2 access. Configure locally:

```bash
aws configure --profile client360-readonly
```

Then set:

```text
AWS_PROFILE=client360-readonly
AWS_REGION=ap-southeast-2
```

