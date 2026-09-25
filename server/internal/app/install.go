// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package app

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/Shaalan15/central/server/internal/setup"
)

// shellQuote quotes s for POSIX shells.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// dearmor converts an ASCII-armored OpenPGP public key to its binary form (what gpgv expects).
func dearmor(armored string) ([]byte, error) {
	var b64 strings.Builder
	sc := bufio.NewScanner(strings.NewReader(armored))
	state := 0 // 0 before BEGIN, 1 headers, 2 body, 3 done
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch state {
		case 0:
			if line == "-----BEGIN PGP PUBLIC KEY BLOCK-----" {
				state = 1
			}
		case 1:
			if line == "" {
				state = 2
			} else if !strings.Contains(line, ":") { // no headers: body starts immediately
				state = 2
				b64.WriteString(line)
			}
		case 2:
			switch {
			case strings.HasPrefix(line, "-----END PGP PUBLIC KEY BLOCK-----"):
				state = 3
			case strings.HasPrefix(line, "="): // CRC24 checksum
			default:
				b64.WriteString(line)
			}
		}
	}
	if state != 3 {
		return nil, errors.New("not an armored OpenPGP public key block")
	}
	return base64.StdEncoding.DecodeString(b64.String())
}

const installScript = `#!/usr/bin/env bash
# Central agent installer for Ubuntu and Debian, served by your Central instance.
#
# Read this script before running it. It installs the central-agent package (verifying its
# signature) and starts enrollment. The enrollment key is prompted for interactively, or read
# from a file with --key-file (use "--key-file -" for stdin). Never put the key on the command
# line: it would end up in the process list and your shell history.
#
# Usage: sudo bash install-agent.sh [--url AGENT_URL] [--key-file FILE] [-- extra enroll options]
set -euo pipefail

AGENT_URL=__AGENT_URL__
RELEASE_URL=__RELEASE_URL__
RELEASE_KEY_B64=__RELEASE_KEY__

die() { echo "install-agent: $*" >&2; exit 1; }

url="$AGENT_URL"
key_file=""
extra=()
while [ $# -gt 0 ]; do
  case "$1" in
    --url) [ $# -ge 2 ] || die "--url needs a value"; url="$2"; shift 2 ;;
    --key-file) [ $# -ge 2 ] || die "--key-file needs a value"; key_file="$2"; shift 2 ;;
    --) shift; extra=("$@"); break ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) die "unknown option $1 (use -- to pass options to central-agent enroll)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run this script as root (sudo)"
[ -r /etc/os-release ] || die "cannot identify the operating system"
. /etc/os-release
case "${ID:-}" in
  ubuntu|debian) ;;
  *) die "unsupported system '${ID:-unknown}': Central agents run on Ubuntu and Debian" ;;
esac
arch="$(dpkg --print-architecture)"
case "$arch" in
  amd64|arm64) ;;
  *) die "unsupported architecture $arch" ;;
esac
[ -n "$url" ] || die "no agent URL: pass --url"

if ! command -v central-agent >/dev/null 2>&1; then
  if [ -z "$RELEASE_URL" ] || [ -z "$RELEASE_KEY_B64" ]; then
    die "this Central has no signed agent release source configured.
Install the central-agent .deb for $arch manually, then run:
  sudo central-agent enroll --url $url"
  fi
  export DEBIAN_FRONTEND=noninteractive
  for tool in curl gpgv sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq curl gpgv coreutils; break; }
  done
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  fetch() { curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/$2" "$RELEASE_URL/$1"; }
  printf '%s' "$RELEASE_KEY_B64" | base64 -d > "$tmp/release.gpg"
  fetch SHA256SUMS SHA256SUMS
  fetch SHA256SUMS.gpg SHA256SUMS.gpg
  gpgv --keyring "$tmp/release.gpg" "$tmp/SHA256SUMS.gpg" "$tmp/SHA256SUMS" 2>/dev/null \
    || die "the release checksums are not signed by the configured release key"
  deb="$(grep -E "^[0-9a-f]{64}  central-agent_[0-9A-Za-z.+~-]+_${arch}\.deb$" "$tmp/SHA256SUMS" | tail -n 1 | awk '{print $2}')"
  [ -n "$deb" ] || die "no central-agent package for $arch in the release"
  fetch "$deb" "$deb"
  (cd "$tmp" && awk -v d="$deb" '$2 == d' SHA256SUMS | sha256sum --check --quiet -) || die "checksum mismatch for $deb"
  apt-get install -y -qq "$tmp/$deb"
fi

args=(enroll --url "$url")
[ -n "$key_file" ] && args+=(--key-file "$key_file")
exec central-agent "${args[@]}" "${extra[@]}"
`

// renderInstallScript fills in the agent URL and release source.
func renderInstallScript(agentURL, releaseURL string, releaseKey []byte) string {
	key := ""
	if len(releaseKey) > 0 {
		key = base64.StdEncoding.EncodeToString(releaseKey)
	}
	return strings.NewReplacer(
		"__AGENT_URL__", shellQuote(agentURL),
		"__RELEASE_URL__", shellQuote(strings.TrimRight(releaseURL, "/")),
		"__RELEASE_KEY__", shellQuote(key),
	).Replace(installScript)
}

func (a *App) releaseKey() []byte {
	if a.Config.Agent.ReleaseKeyFile == "" {
		return nil
	}
	data, err := os.ReadFile(a.Config.Agent.ReleaseKeyFile)
	if err != nil {
		a.Log.Warn("cannot read the agent release key", "path", a.Config.Agent.ReleaseKeyFile, "error", err)
		return nil
	}
	key, err := dearmor(string(data))
	if err != nil {
		a.Log.Warn("the agent release key is not an armored OpenPGP public key", "path", a.Config.Agent.ReleaseKeyFile, "error", err)
		return nil
	}
	return key
}

// serveInstallScript serves /install-agent.sh.
func (a *App) serveInstallScript(w http.ResponseWriter, r *http.Request) {
	if !a.Setup.Complete() {
		http.NotFound(w, r)
		return
	}
	script := renderInstallScript(a.Deps.AgentURL(r.Context()), a.Config.Agent.ReleaseURL, a.releaseKey())
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Disposition", `inline; filename="install-agent.sh"`)
	_, _ = w.Write([]byte(script))
}

// serveDiscovery serves /.well-known/central-agent.json: the agent URL and the CA pin, so an
// agent given only the UI hostname can find the agent endpoint. The agent accepts it only if
// the pin matches the one in its enrollment key.
func (a *App) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	if !a.Setup.Complete() || !a.PKI.Loaded() {
		http.NotFound(w, r)
		return
	}
	st := a.Holder.Get()
	agentURL := a.Config.AgentURL
	if agentURL == "" && st != nil {
		agentURL, _ = st.GetSetting(r.Context(), setup.SettingAgentURL)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(map[string]string{"agent_url": agentURL, "ca_pin": a.PKI.Pin()})
}
