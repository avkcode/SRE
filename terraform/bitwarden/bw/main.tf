provider "aws" {
  region = var.region
}

# Security Group for web server access
resource "aws_security_group" "allow_ssh" {
  name        = var.security_group_name
  description = var.security_group_description

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_cidr_blocks
  }

  ingress {
    from_port   = var.bitwarden_port
    to_port     = var.bitwarden_port
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

# EC2 Instance with Docker auto-install
resource "aws_instance" "bw_vm" {
  ami           = var.ami
  instance_type = var.instance_type
  key_name      = var.key_name
  security_groups = [aws_security_group.allow_ssh.name]

  # First create the tarball locally
  provisioner "local-exec" {
    command = "tar -czf bw-docker.tar.gz -C bw-docker ."
  }

  # Copy and execute deps.sh
  provisioner "file" {
    source      = "deps.sh"
    destination = "/home/ubuntu/deps.sh"
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("${var.key_name}.pem")
      host        = self.public_ip
    }
  }

  provisioner "file" {
    source      = "bw-docker.tar.gz"
    destination = "/home/ubuntu/bw-docker.tar.gz"
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("${var.key_name}.pem")
      host        = self.public_ip
    }
  }

  provisioner "remote-exec" {
    inline = [
      "chmod +x /home/ubuntu/deps.sh",
      "/home/ubuntu/deps.sh",
      "mkdir -p /home/ubuntu/bw-docker",
      "tar -xzf /home/ubuntu/bw-docker.tar.gz -C /home/ubuntu/bw-docker",
      "cd /home/ubuntu/bw-docker",
      "sudo docker-compose up -d"
    ]
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("${var.key_name}.pem")
      host        = self.public_ip
    }
  }

  tags = var.instance_tags
}

output "instance_public_ip" {
  value = aws_instance.bw_vm.public_ip
}

output "bitwarden_access_url" {
  value = "https://${aws_instance.bw_vm.public_ip}:${var.bitwarden_port}"
}
