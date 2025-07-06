variable "region" {
  description = "AWS region"
  type        = string
  default     = "eu-central-1"
}

variable "ami" {
  description = "AMI ID for the EC2 instance"
  type        = string
}

variable "instance_type" {
  description = "Instance type for the EC2 instance"
  type        = string
}

variable "key_name" {
  description = "Name of the SSH key pair"
  type        = string
}

variable "security_group_name" {
  description = "Name of the security group"
  type        = string
}

variable "security_group_description" {
  description = "Description of the security group"
  type        = string
}

variable "ssh_cidr_blocks" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
}

variable "bitwarden_port" {
  description = "Port for Bitwarden access"
  type        = number
}

variable "instance_tags" {
  description = "Tags for the EC2 instance"
  type        = map(string)
}
