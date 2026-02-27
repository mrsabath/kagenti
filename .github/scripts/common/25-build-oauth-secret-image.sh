#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../lib/env-detect.sh"
source "$SCRIPT_DIR/../lib/logging.sh"

log_step "25" "Building ui-oauth-secret image from source"

if [ "$IS_OPENSHIFT" = "true" ]; then
    log_info "Skipping local build on OpenShift (uses pre-built image)"
    exit 0
fi

IMAGE_NAME="$(grep -A5 'uiOAuthSecret:' "$REPO_ROOT/charts/kagenti/values.yaml" | grep 'image:' | grep -v '#' | awk '{print $2}')"
IMAGE_TAG="$(grep -A5 'uiOAuthSecret:' "$REPO_ROOT/charts/kagenti/values.yaml" | grep 'tag:' | awk '{print $2}')"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

log_info "Building image: ${FULL_IMAGE}"
docker build -t "${FULL_IMAGE}" \
    -f "$REPO_ROOT/kagenti/auth/ui-oauth-secret/Dockerfile" \
    "$REPO_ROOT/kagenti/"

CLUSTER_NAME="${KIND_CLUSTER_NAME:-kagenti}"
log_info "Loading image into Kind cluster '${CLUSTER_NAME}'..."
kind load docker-image "${FULL_IMAGE}" --name "${CLUSTER_NAME}"

NAMESPACE="kagenti-system"
JOB_NAME="kagenti-ui-oauth-secret-job"

EXISTING=$(kubectl get job "$JOB_NAME" -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || echo "")
if [ "$EXISTING" != "True" ]; then
    log_info "Restarting oauth-secret job with updated image..."
    kubectl delete job "$JOB_NAME" -n "$NAMESPACE" --ignore-not-found
    sleep 2

    helm get values kagenti -n "$NAMESPACE" -o yaml > /tmp/kagenti-values.yaml 2>/dev/null || true
    helm upgrade kagenti "$REPO_ROOT/charts/kagenti" -n "$NAMESPACE" \
        --reuse-values --no-hooks 2>/dev/null || true

    log_info "Waiting for oauth-secret job to complete..."
    kubectl wait --for=condition=complete job \
        -l app.kubernetes.io/component=oauth-secret \
        -n "$NAMESPACE" --timeout=120s || {
        log_error "OAuth secret job did not complete"
        kubectl logs job/"$JOB_NAME" -n "$NAMESPACE" || true
        exit 1
    }
    log_info "Restarting kagenti-ui to pick up the new secret..."
    kubectl rollout restart deployment/kagenti-ui -n "$NAMESPACE"
    kubectl rollout status deployment/kagenti-ui -n "$NAMESPACE" --timeout=120s
fi

log_success "ui-oauth-secret image built and loaded"
