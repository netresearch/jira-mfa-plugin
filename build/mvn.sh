#!/usr/bin/env bash
# Runs Maven inside Docker, so the host needs neither Java nor Maven.
# The local repository lives in a host directory owned by the calling user
# (default ~/.cache/jira-mfa-m2, override with MAVEN_CACHE). A named Docker
# volume would be created root-owned and Maven, running as the calling user,
# could not write to it on a fresh machine.
# Usage: build/mvn.sh <maven arguments>, e.g. build/mvn.sh -B package
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${MAVEN_IMAGE:-maven:3.9.9-eclipse-temurin-11}"
cache="${MAVEN_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/jira-mfa-m2}"
mkdir -p "$cache"
exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e MAVEN_CONFIG=/var/maven/.m2 \
  -e HOME=/var/maven \
  -v "$cache":/var/maven/.m2 \
  -v "$root":/work -w /work \
  "$image" \
  mvn -Duser.home=/var/maven -s /work/build/maven-settings.xml "$@"
