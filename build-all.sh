#!/usr/bin/env bash
set -euo pipefail

projects=(
  digital-product-passport
  identity-kyc
  nft-ownership
  personhood-airdrop
  private-voting
  proof-of-reserves
  selective-disclosure
)

if [ "$#" -eq 0 ]; then
  set -- build
fi

for project in "${projects[@]}"; do
  printf '\n==> %s: ./gradlew' "$project"
  printf ' %q' "$@"
  printf '\n'
  (cd "$project" && ./gradlew "$@")
done
