#!/usr/bin/env bash
set -euo pipefail

security_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
generated_dir="${security_root}/security/generated"
mkdir -p "${generated_dir}"
set -a
source "${security_root}/security/tool-versions.env"
set +a

run_models() {
  node "${security_root}/scripts/validate-security-models.mjs"
  node "${security_root}/scripts/validate-compose-security.mjs"
  mkdir -p "${generated_dir}/threagile"
  docker run --rm \
    --platform linux/amd64 \
    -v "${security_root}:/app/work:ro" \
    -v "${generated_dir}/threagile:/app/output" \
    "${THREAGILE_IMAGE}" \
    --model /app/work/security/threagile/threagile.yaml \
    --output /app/output \
    --generate-report-pdf=false \
    --generate-risks-excel=false \
    --generate-tags-excel=false
}

run_gitleaks() {
  mkdir -p "${generated_dir}/gitleaks"
  docker run --rm \
    -v "${security_root}:/repo:ro" \
    -v "${generated_dir}/gitleaks:/reports" \
    "${GITLEAKS_IMAGE}" dir /repo \
    --config /repo/security/gitleaks.toml --redact --report-format json --report-path /reports/worktree.json
  git -C "${security_root}" log --all --full-history -p | docker run --rm -i \
    -v "${security_root}:/repo:ro" \
    -v "${generated_dir}/gitleaks:/reports" \
    "${GITLEAKS_IMAGE}" stdin \
    --config /repo/security/gitleaks.toml --redact --report-format json --report-path /reports/history.json
}

run_trivy_repo() {
  mkdir -p "${generated_dir}/trivy"
  node "${security_root}/scripts/validate-compose-security.mjs"
  docker run --rm \
    -v "${security_root}:/repo:ro" \
    -v "${generated_dir}/trivy:/reports" \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" fs --disable-telemetry --scanners vuln,misconfig,secret --skip-dirs /repo/node_modules --skip-dirs /repo/security/generated --format json --output /reports/repository.json /repo
  docker run --rm \
    -v "${security_root}:/repo:ro" \
    -v "${generated_dir}/trivy:/reports" \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" config --disable-telemetry --format json --output /reports/dockerfile.json /repo/Dockerfile
  docker run --rm \
    -v "${security_root}:/repo:ro" \
    -v "${generated_dir}/trivy:/reports" \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" config --disable-telemetry --format json --output /reports/compose.json /repo/compose.yaml
  docker run --rm \
    -v "${security_root}:/repo:ro" \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" fs --disable-telemetry --scanners vuln,misconfig,secret --skip-dirs /repo/node_modules --skip-dirs /repo/security/generated --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 /repo
}

run_trivy_image() {
  mkdir -p "${generated_dir}/trivy"
  rootfs_dir="$(mktemp -d "${TMPDIR:-/tmp}/entra-rootfs.XXXXXX")"
  container_id="$(docker create entra-relationship-explorer-app:local)"
  cleanup_image_scan() {
    docker rm -f "${container_id}" >/dev/null 2>&1 || true
    rm -rf "${rootfs_dir}"
  }
  trap cleanup_image_scan EXIT
  docker export "${container_id}" | tar -xf - -C "${rootfs_dir}"
  docker run --rm \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" clean --scan-cache
  docker run --rm \
    -v "${rootfs_dir}:/rootfs:ro" \
    -v "${generated_dir}/trivy:/reports" \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" rootfs --disable-telemetry --scanners vuln,secret --format json --output /reports/app-image.json /rootfs
  node "${security_root}/scripts/gate-trivy-report.mjs" \
    "${generated_dir}/trivy/app-image.json" \
    "${rootfs_dir}" \
    "${security_root}/security/trivy/triage.json"
}

run_sbom() {
  mkdir -p "${generated_dir}/sbom"
  rootfs_dir="$(mktemp -d "${TMPDIR:-/tmp}/entra-sbom.XXXXXX")"
  container_id="$(docker create entra-relationship-explorer-app:local)"
  cleanup_sbom() {
    docker rm -f "${container_id}" >/dev/null 2>&1 || true
    rm -rf "${rootfs_dir}"
  }
  trap cleanup_sbom EXIT
  docker export "${container_id}" | tar -xf - -C "${rootfs_dir}"
  docker run --rm \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" clean --scan-cache
  docker run --rm \
    -v "${rootfs_dir}:/rootfs:ro" \
    -v "${generated_dir}/sbom:/reports" \
    -v entra-security-trivy-cache:/root/.cache/trivy \
    "${TRIVY_IMAGE}" rootfs --disable-telemetry --format cyclonedx --output /reports/entra-relationship-explorer-app.cdx.json /rootfs
}

run_zap() {
  mkdir -p "${generated_dir}/zap"
  docker run --rm \
    --network entra-relationship-explorer_default \
    -v "${security_root}/security/zap:/zap/config:ro" \
    -v "${generated_dir}/zap:/zap/wrk" \
    "${ZAP_IMAGE}" zap.sh -cmd -autorun /zap/config/automation.yaml
}

case "${1:-}" in
  models) run_models ;;
  gitleaks) run_gitleaks ;;
  trivy-repo) run_trivy_repo ;;
  trivy-image) run_trivy_image ;;
  sbom) run_sbom ;;
  zap) run_zap ;;
  *) echo "Usage: $0 {models|gitleaks|trivy-repo|trivy-image|sbom|zap}" >&2; exit 64 ;;
esac
