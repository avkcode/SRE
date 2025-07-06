provider "aws" {
  region = "eu-central-1"
}

# Add random provider for password generation
provider "random" {}

# Add local provider for file creation
provider "local" {}

# Generate a secure random password
resource "random_password" "db_password" {
  length           = 16
  special          = true
  min_lower        = 1
  min_upper        = 1
  min_numeric      = 1
  min_special      = 1
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Create a Security Group for the Aurora DB
resource "aws_security_group" "aurora_sg" {
  name        = "aurora-db-sg"
  description = "Allow inbound traffic for Aurora DB"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Create an Aurora PostgreSQL DB Cluster
resource "aws_rds_cluster" "aurora_postgres" {
  cluster_identifier      = "aurora-postgres-cluster"
  engine                  = "aurora-postgresql"
  engine_version          = "14.17"
  master_username         = "root"
  master_password         = random_password.db_password.result
  db_subnet_group_name    = aws_db_subnet_group.aurora_subnet_group.name
  vpc_security_group_ids  = [aws_security_group.aurora_sg.id]
  backup_retention_period = 5
  preferred_backup_window = "07:00-09:00"
  skip_final_snapshot     = true # Set to false for production environments
}

# Create a DB Subnet Group for the Aurora Cluster
resource "aws_db_subnet_group" "aurora_subnet_group" {
  name       = "aurora-postgres-subnet-group"
  subnet_ids = ["subnet-03a49bcbd4b153e72", "subnet-0f35c4525005a0014"]

  tags = {
    Name = "Aurora-Postgres-Subnet-Group"
  }
}

# Create an Aurora DB Instance
resource "aws_rds_cluster_instance" "aurora_postgres_instance" {
  identifier         = "aurora-postgres-instance"
  cluster_identifier = aws_rds_cluster.aurora_postgres.id
  instance_class     = "db.t3.medium"
  engine             = aws_rds_cluster.aurora_postgres.engine
  engine_version     = aws_rds_cluster.aurora_postgres.engine_version
}

# Output the Aurora DB endpoint and other connection information
output "aurora_db_endpoint" {
  description = "The endpoint of the Aurora DB cluster"
  value       = aws_rds_cluster.aurora_postgres.endpoint
}

output "db_port" {
  description = "The port on which the DB accepts connections"
  value       = 5432
}

output "db_connection_string" {
  description = "PostgreSQL connection string (without password)"
  value       = "postgresql://root@${aws_rds_cluster.aurora_postgres.endpoint}:5432/"
}

# Save credentials to a local file
resource "local_file" "db_credentials" {
  filename        = "${path.module}/db_credentials.txt"
  content         = <<-EOT
    Host       = ${aws_rds_cluster.aurora_postgres.endpoint}
    Port       = 5432
    Database   = postgres
    Username   = root
    Password   = ${random_password.db_password.result}
    
    Connection string: postgresql://root:${random_password.db_password.result}@${aws_rds_cluster.aurora_postgres.endpoint}:5432/postgres
  EOT
  file_permission = "0600" # Only owner can read and write
}

# Output the password for reference (sensitive, will be hidden in output)
output "db_password" {
  description = "The generated database password"
  value       = random_password.db_password.result
  sensitive   = true
}
