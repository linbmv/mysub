#!/usr/bin/env bash
set -euo pipefail

WORKER_URL="${1:-}"
ADMIN_SECRET="${2:-}"

if [ -z "$WORKER_URL" ] || [ -z "$ADMIN_SECRET" ]; then
  echo "Usage: $0 <worker-url> <admin-secret>"
  echo ""
  echo "Example:"
  echo "  $0 https://mysub.example.workers.dev 'your-admin-secret'"
  echo ""
  exit 1
fi

# Remove trailing slash
WORKER_URL="${WORKER_URL%/}"

echo "Uploading configuration to $WORKER_URL/admin/config"
echo ""
echo "Please provide the following configuration values:"
echo "(Press Enter to skip optional values)"
echo ""

read -p "MAIN_SUB_URL (required): " MAIN_SUB_URL
read -p "BOOTSTRAP_SUB_URL (optional): " BOOTSTRAP_SUB_URL
read -p "HOME_SECRET_RULE_URL (optional): " HOME_SECRET_RULE_URL
read -p "SENSITIVE_RULE_URL (optional): " SENSITIVE_RULE_URL
read -p "ALLOWED_TOKENS (optional, comma-separated): " ALLOWED_TOKENS
read -p "PUBLIC_BASE_URL (optional, defaults to worker URL): " PUBLIC_BASE_URL

if [ -z "$MAIN_SUB_URL" ]; then
  echo ""
  echo "Error: MAIN_SUB_URL is required"
  exit 1
fi

CONFIG_JSON=$(cat <<EOF
{
  "admin": "$ADMIN_SECRET",
  "MAIN_SUB_URL": "$MAIN_SUB_URL",
  "BOOTSTRAP_SUB_URL": "$BOOTSTRAP_SUB_URL",
  "HOME_SECRET_RULE_URL": "$HOME_SECRET_RULE_URL",
  "SENSITIVE_RULE_URL": "$SENSITIVE_RULE_URL",
  "ALLOWED_TOKENS": "$ALLOWED_TOKENS",
  "PUBLIC_BASE_URL": "$PUBLIC_BASE_URL"
}
EOF
)

echo ""
echo "Uploading configuration..."

RESPONSE=$(curl -s -w "\n%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d "$CONFIG_JSON" \
  "$WORKER_URL/admin/config")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "200" ]; then
  echo "✓ Configuration uploaded successfully"
  echo ""
  echo "$BODY" | jq -r '.config | to_entries | .[] | "  \(.key): \(.value)"' 2>/dev/null || echo "$BODY"
else
  echo "✗ Upload failed (HTTP $HTTP_CODE)"
  echo "$BODY"
  exit 1
fi
