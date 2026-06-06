#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

GIT_BRANCH="${GIT_BRANCH:-main}"
WEB_USER="${WEB_USER:-www-data}"
WEB_GROUP="${WEB_GROUP:-www-data}"
DOCKER_CONTAINER="${DOCKER_CONTAINER:-amtgard-idp}"
CONTAINER_APP_DIR="${CONTAINER_APP_DIR:-/var/www/idp.amtgard.com}"
COMPOSER_FLAGS="${COMPOSER_FLAGS:---no-dev --optimize-autoloader --ignore-platform-reqs}"
PHINX_ENV="${PHINX_ENV:-production}"

chown_app() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        chown -R "${WEB_USER}:${WEB_GROUP}" .
        return
    fi

    if command -v sudo >/dev/null 2>&1; then
        sudo chown -R "${WEB_USER}:${WEB_GROUP}" .
        return
    fi

    echo "install.sh: chown requires root or sudo." >&2
    exit 1
}

require_container() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "install.sh: docker is required but not installed." >&2
        exit 1
    fi

    if ! docker ps --format '{{.Names}}' | grep -Fxq "$DOCKER_CONTAINER"; then
        echo "install.sh: container '${DOCKER_CONTAINER}' is not running." >&2
        exit 1
    fi
}

run_in_container() {
    docker exec -u "$WEB_USER" -w "$CONTAINER_APP_DIR" "$DOCKER_CONTAINER" "$@"
}

echo "==> Pulling latest from ${GIT_BRANCH}..."
git fetch origin "$GIT_BRANCH"
git checkout "$GIT_BRANCH"
git pull --ff-only origin "$GIT_BRANCH"

echo "==> Setting ownership to ${WEB_USER}:${WEB_GROUP}..."
chown_app

require_container

echo "==> Installing Composer dependencies in ${DOCKER_CONTAINER}..."
read -r -a composer_flags <<< "$COMPOSER_FLAGS"
run_in_container composer install "${composer_flags[@]}"

echo "==> Running Phinx migrations (${PHINX_ENV}) in ${DOCKER_CONTAINER}..."
run_in_container vendor/bin/phinx migrate -e "$PHINX_ENV"

echo "==> Install complete."
