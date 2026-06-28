#!/usr/bin/env sh
set -eu

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 https://sub.example.com ADMIN_SECRET" >&2
  exit 1
fi

BASE_URL="$1"
ADMIN_SECRET="$2"

curl -fsS -X POST "$BASE_URL/admin/update-template" \
  -F "admin=$ADMIN_SECRET" \
  -F "type=clash" \
  -F "template=@clash.yaml"

printf '\n'

curl -fsS -X POST "$BASE_URL/admin/update-template" \
  -F "admin=$ADMIN_SECRET" \
  -F "type=shadowrocket" \
  -F "template=@ss.conf"

printf '\n'
