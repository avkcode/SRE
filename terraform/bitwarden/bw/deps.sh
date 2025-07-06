#!/bin/bash

echo "Updating system packages in non-interactive mode..."
sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -yq  # -q for quieter output

echo "Installing docker.io and git in non-interactive mode..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq docker.io git

echo "Starting and enabling Docker service..."
sudo systemctl start docker
sudo systemctl enable docker

echo "Downloading and installing latest docker-compose..."

COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)

sudo curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

sudo chmod +x /usr/local/bin/docker-compose

sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose 2>/dev/null || true

echo -e "\nInstallation complete. Versions:"
docker --version
docker-compose --version

sudo usermod -aG docker ubuntu
