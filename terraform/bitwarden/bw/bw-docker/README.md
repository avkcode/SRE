# Setup

## 1. DB password
Writes the PostgreSQL database password into a file named postgres_password.txt. This file will be used as a Docker secret to securely pass the password to the database container.
```
echo "Super1strong2password" > postgres_password.txt
```

`data` holds persistent data such as PostgreSQL database files ensuring data survives container restarts:
```
mkdir data
```

## 2. Generate certs
bw_certs.sh generates self-signed SSL certificates for development or testing purposes:
```
./bw_certs.sh localhost
```

```
ls ssl/
cert.pem  dhparam.pem  key.pem
```

## 3. Adjust .settings.env

Replace placeholders like BW_DOMAIN, BW_DB_PASSWORD, BW_INSTALLATION_ID, and BW_INSTALLATION_KEY with actual values.

```
#####################
# Required Settings #
#####################

# Server hostname
BW_DOMAIN=<>

# Database
# Available providers are sqlserver, postgresql, mysql/mariadb, or sqlite
BW_DB_PROVIDER=postgresql
BW_DB_SERVER=db
BW_DB_DATABASE=bitwarden_vault
BW_DB_USERNAME=bitwarden
BW_DB_PASSWORD=<>

# Installation information
# Get your ID and key from https://bitwarden.com/host/
BW_INSTALLATION_ID=<>
BW_INSTALLATION_KEY=<>

globalSettings__databaseProvider=postgresql
connectionStrings__vault=Host=db;Database=bitwarden_vault;Username=bitwarden;Password=<>;
globalSettings__installation__id=<>
globalSettings__installation__key=<>
```

After adjustments:
`mv .settings.env settings.env`

## 4. Start docker-compose

Start the services in detached mode:
```
docker-compose up -d
```

Monitor Logs :
```
docker-compose logs -f
```

### Files

- bitwarden-ssl.conf contains Nginx configuration for SSL settings and HTTPS redirection to secure web traffic.
- bw_settings.py is a Python script used to generate or manage environment variables for the Bitwarden setup dynamically.
- docker-compose.yml defines services like Bitwarden and PostgreSQL in Docker containers including their networks ports and volumes.
- entrypoint.sh is the startup script for configuring the Bitwarden container such as setting up users certificates and application settings.
- ssl is a directory storing SSL certificate files including private keys and public certificates for securing connections.
- bw_certs.sh generates self-signed SSL certificates for development or testing purposes when proper certificates are unavailable.
- data holds persistent data such as PostgreSQL database files ensuring data survives container restarts.
- Dockerfile defines the blueprint for building the custom Docker image tailored for running the Bitwarden application.
- postgres_password.txt stores the PostgreSQL password securely used by Docker secrets to avoid hardcoding sensitive credentials.
- settings.env contains environment variables like database connection strings domain names and service configurations required for Bitwarden operation.
