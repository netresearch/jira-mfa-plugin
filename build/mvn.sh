#!/usr/bin/env bash
# Runs Maven inside Docker, so the host needs neither Java nor Maven.
# The local repository lives in the Docker volume jira-mfa-m2.
# Usage: build/mvn.sh <maven arguments>, e.g. build/mvn.sh -B package
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="${MAVEN_IMAGE:-maven:3.9.9-eclipse-temurin-11}"
exec docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e MAVEN_CONFIG=/var/maven/.m2 \
  -e HOME=/var/maven \
  -v jira-mfa-m2:/var/maven/.m2 \
  -v "$root":/work -w /work \
  "$image" \
  mvn -Duser.home=/var/maven -s /work/build/maven-settings.xml "$@"
