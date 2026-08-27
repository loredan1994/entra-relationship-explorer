#!/bin/zsh
set -euo pipefail

# Starts the live local stack against a tenant you control.
#
# Secrets are never read from the repository. Provide them one of two ways:
#
#   1. Azure Key Vault (set ENTRA_KEY_VAULT_NAME). Requires the Azure CLI and
#      an active `az login`. Secret names are listed below.
#   2. A local env file at .env.local, which is git-ignored. Copy
#      apps/web/.env.example and fill it in.
#
# Required in either case: ENTRA_TENANT_ID and ENTRA_CLIENT_ID for your own
# app registration. See CONTRIBUTING.md for the registration steps.

if [[ -n "${ENTRA_KEY_VAULT_NAME:-}" ]]; then
  vault_secret() {
    az keyvault secret show --vault-name "$ENTRA_KEY_VAULT_NAME" --name "$1" --query value --output tsv
  }
  export ENTRA_CLIENT_SECRET="$(vault_secret entra-relationship-explorer-local-client-secret)"
  export ENTRA_DATA_ENCRYPTION_KEY="$(vault_secret entra-relationship-explorer-local-data-key)"
  export POSTGRES_PASSWORD="$(vault_secret entra-relationship-explorer-local-postgres-password)"
elif [[ -f "${0:A:h}/../.env.local" ]]; then
  set -a
  source "${0:A:h}/../.env.local"
  set +a
else
  print -u2 "No credential source. Set ENTRA_KEY_VAULT_NAME, or create .env.local from apps/web/.env.example."
  exit 1
fi

export POSTGRES_PASSWORD_URL_ENCODED="$(node -e 'process.stdout.write(encodeURIComponent(process.env.POSTGRES_PASSWORD))')"

docker compose build web
exec docker compose up --no-build -d --wait
