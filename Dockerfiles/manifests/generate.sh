#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

if sed --version 2>/dev/null | grep -q "GNU sed"; then
    SED=sed
elif gsed --version 2>/dev/null | grep -q "GNU sed"; then
    SED=gsed
fi

cd "$(dirname "$0")"

helm repo update

TMPDIR=$(mktemp -d)
trap 'rm -r $TMPDIR' EXIT

cat > "$TMPDIR/values-agent-only.yaml" <<EOF
datadog:
  processAgent:
    enabled: false
EOF

cat > "$TMPDIR/values-all-containers.yaml" <<EOF
datadog:
  logs:
    enabled: true
  apm:
    enabled: true
  processAgent:
    enabled: true
  systemProbe:
    enabled: true
EOF

cat > "$TMPDIR/values-cluster-agent.yaml" <<EOF
datadog:
  processAgent:
    enabled: false
clusterAgent:
  enabled: true
EOF

cat > "$TMPDIR/values-cluster-checks-runners.yaml" <<EOF
datadog:
  processAgent:
    enabled: false
  clusterChecks:
    enabled: true
clusterAgent:
  enabled: true
clusterChecksRunner:
  enabled: true
EOF

cat > "$TMPDIR/cleanup_instructions.yaml" <<EOF
- command: delete
  path: metadata.labels."helm.sh/chart"
- command: delete
  path: metadata.labels."app.kubernetes.io/*"
- command: delete
  path: spec.template.metadata.annotations.checksum/*
EOF

for values in "$TMPDIR"/values-*.yaml; do
    type=${values##*values-}
    type=${type%.yaml}

    rm -rf "${type:?}"
    mkdir "${type:?}"

    helm template --namespace default datadog-agent "${HELM_DATADOG_CHART:-stable/datadog}" --values "$values" --output-dir "$TMPDIR/generated_$type"
    for file in "$TMPDIR/generated_$type"/datadog/templates/*.yaml; do
        # Skip files containing only comments like `containers-common-env.yaml`
        if [[ "$(yq read --length "$file")" == 0 ]]; then
            rm "$file"
            continue
        fi
        ${SED:-sed} -i 's/^# Source: \(.*\)/# This file has been generated by `helm template datadog-agent stable\/datadog` from \1. Please re-run `generate.sh` rather than modifying this file manually./' "$file"
        yq write -d'*' --script "$TMPDIR"/cleanup_instructions.yaml "$file" > "$type/$(basename "$file")"
        ${SED:-sed} -i 's/\(api-key: \)".*"/\1PUT_YOUR_BASE64_ENCODED_API_KEY_HERE/; s/\(token: \).*/\1PUT_A_BASE64_ENCODED_RANDOM_STRING_HERE/' "$type/$(basename "$file")"
    done

    cat > "$type/README.md" <<EOF
The kubernetes manifests found in this directory have been automatically generated
from the [helm chart \`stable/datadog\`](https://github.com/helm/charts/tree/master/stable/datadog)
version $(helm show chart stable/datadog | yq r - version) with the following \`values.yaml\`:

\`\`\`yaml
$(<"$values")
\`\`\`
EOF
done