#!/bin/zsh
set -euo pipefail

export ENTRA_CLIENT_SECRET="$(az keyvault secret show --vault-name your-key-vault --name entra-relationship-explorer-local-client-secret --query value --output tsv)"
export ENTRA_DATA_ENCRYPTION_KEY="$(az keyvault secret show --vault-name your-key-vault --name entra-relationship-explorer-local-data-key --query value --output tsv)"
export POSTGRES_PASSWORD="$(az keyvault secret show --vault-name your-key-vault --name entra-relationship-explorer-local-postgres-password --query value --output tsv)"
export POSTGRES_PASSWORD_URL_ENCODED="$(node -e 'process.stdout.write(encodeURIComponent(process.env.POSTGRES_PASSWORD))')"

docker compose build web
exec docker compose up --no-build -d --wait
