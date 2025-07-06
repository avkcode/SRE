# Bitwarden (Self-Hosted) + AWS RDS Deployment  

### **Overview**  
- **Terraform + Docker Compose** setup for self-hosted Bitwarden with **AWS RDS PostgreSQL** as backend.  
- Includes SSL (HTTPS), automated certs, and infrastructure-as-code (IaC) deployment.  

### **Key Files**  
- **`docker-compose.yml`** – Runs `bitwarden` with:  
  - Nginx (SSL termination)  
  - Optional built-in PostgreSQL (or external RDS)  
- **Terraform (`main.tf`)** – Provisions AWS resources:  
  - **RDS PostgreSQL** (database backend)  
  - Security groups, IAM roles, etc.  
- **SSL Certs** – Pre-configured or auto-generated (via `bw_certs.sh`).  

### **Deployment Steps**  
1. **AWS Setup**: Terraform applies RDS + networking.  
2. **Docker**: `docker-compose up` with `settings.env` (DB connection vars).  
3. **SSL**: Optional Let’s Encrypt or manual certs.  

### **Notes**  
- **Backups**: Ensure RDS snapshots/backups are configured.

# Aurora PostgreSQL Database Setup

Terraform configuration for provisioning an AWS Aurora PostgreSQL database cluster with secure credentials management.

## Prerequisites

- AWS CLI configured with appropriate credentials
- Terraform v1.0.0+
- Valid VPC with at least two subnets in different availability zones

## Quick Start

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Apply the configuration
terraform apply
```

After successful deployment, connection credentials will be saved to `db_credentials.txt` in the current directory.

## Configuration

Key variables:

- `region`: AWS region (default: eu-central-1)
- `instance_class`: DB instance type (default: db.t3.medium)
- `engine_version`: PostgreSQL version (default: 14.17)
- `security_group`: Security group with port 5432 open

## Security

- Database password is randomly generated
- Credentials file has restricted permissions (0600)
- Connection string is available as a Terraform output

