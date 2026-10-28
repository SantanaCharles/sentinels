#!/bin/sh
# Instalador do Sentinels (Linux com systemd: Debian, Ubuntu, RHEL, Rocky, Alma…).
#
#   curl -fsSL https://github.com/SantanaCharles/sentinels/releases/latest/download/install.sh | sudo sh
#   sudo sh install.sh --version v0.1.0     # versão específica
#   sudo sh install.sh --from ./dist        # a partir de uma pasta local (mesmos arquivos da release)
#   sudo sh install.sh --uninstall [--purge]
#   sudo sh install.sh --no-setup           # não oferecer o assistente no final
#   sudo sh install.sh --cli-only           # só o comando sentinels (para quem roda o agente em Docker/Portainer)
#
# O que faz: baixa o binário e confere o SHA-256, cria o usuário de sistema
# "sentinels", instala o serviço systemd e cria a configuração SEM sobrescrever
# a existente. Não inicia o serviço sozinho: você revisa a configuração antes.
set -eu

REPO="SantanaCharles/sentinels"
VERSION="latest"
FROM=""
UNINSTALL=0
PURGE=0
START=0
SETUP=1
CLI_ONLY=0

BIN=/usr/local/bin/sentinels
ETC=/etc/sentinels
VAR=/var/lib/sentinels
UNIT=/etc/systemd/system/sentinels.service

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33maviso:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merro:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version precisa de um valor}"; shift 2 ;;
    --from) FROM="${2:?--from precisa de uma pasta}"; shift 2 ;;
    --start) START=1; shift ;;
    --no-setup) SETUP=0; shift ;;
    --cli-only) CLI_ONLY=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) die "opção desconhecida: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "rode como root (sudo)"
command -v systemctl >/dev/null 2>&1 || die "systemd não encontrado; use a instalação via Docker (deploy/docker-compose.yml)"

if [ "$UNINSTALL" -eq 1 ]; then
  say "removendo o serviço e o binário"
  systemctl disable --now sentinels.service 2>/dev/null || true
  rm -f "$UNIT" "$BIN"
  systemctl daemon-reload
  if [ "$PURGE" -eq 1 ]; then
    say "apagando configuração, memória local e usuário (--purge)"
    rm -rf "$ETC" "$VAR"
    if id sentinels >/dev/null 2>&1; then
      userdel sentinels 2>/dev/null || true
    fi
  else
    say "configuração em $ETC e dados em $VAR foram mantidos (use --purge para apagar)"
  fi
  exit 0
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "arquitetura não suportada: $(uname -m)" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

fetch() { # fetch <arquivo da release> <destino>
  if [ -n "$FROM" ]; then
    [ -f "$FROM/$1" ] || die "$FROM/$1 não encontrado"
    cp "$FROM/$1" "$2"
    return
  fi
  if [ "$VERSION" = latest ]; then
    url="https://github.com/$REPO/releases/latest/download/$1"
  else
    url="https://github.com/$REPO/releases/download/$VERSION/$1"
  fi
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$url" || die "falha ao baixar $url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q --https-only -O "$2" "$url" || die "falha ao baixar $url"
  else
    die "instale curl ou wget"
  fi
}

ASSET="sentinels_linux_$ARCH"
say "baixando $ASSET ($VERSION)"
fetch checksums.txt "$TMP/checksums.txt"
for f in "$ASSET" sentinels.example.yaml sentinels.env.example sentinels.service; do
  fetch "$f" "$TMP/$f"
done

say "conferindo SHA-256"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum não encontrado (pacote coreutils)"
( cd "$TMP" && for f in "$ASSET" sentinels.example.yaml sentinels.env.example sentinels.service; do
    line=$(grep "  $f\$" checksums.txt) || { echo "sem checksum para $f" >&2; exit 1; }
    printf '%s\n' "$line" | sha256sum -c --quiet - || exit 1
  done ) || die "checksum não confere: arquivo corrompido ou adulterado. Nada foi instalado."

say "instalando $BIN"
install -m 0755 "$TMP/$ASSET" "$BIN"
"$BIN" version

if [ "$CLI_ONLY" -eq 1 ]; then
  cat <<EOF

Comando sentinels instalado (sem serviço: o agente continua rodando no Docker).
Na pasta da instalação Docker (onde está o sentinels.yaml):
  cd ~/sentinels/deploy && sudo sentinels setup
EOF
  exit 0
fi

if ! id sentinels >/dev/null 2>&1; then
  say "criando usuário de sistema 'sentinels'"
  useradd --system --home-dir "$VAR" --no-create-home --shell /usr/sbin/nologin sentinels
fi
for g in docker adm systemd-journal; do
  if getent group "$g" >/dev/null 2>&1; then
    usermod -aG "$g" sentinels
  fi
done
getent group docker >/dev/null 2>&1 || warn "grupo docker não existe: o agente não verá containers (Docker instalado?)"
if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && [ ! -s /etc/pki/tls/certs/ca-bundle.crt ]; then
  warn "certificados de CA ausentes: o agente não conseguirá baixar KEV/EPSS/feed nem usar HTTPS. Instale: apt install ca-certificates (ou dnf install ca-certificates)"
fi

install -d -m 0750 -o root -g sentinels "$ETC" "$ETC/skills"
install -d -m 0750 -o sentinels -g sentinels "$VAR"
if [ ! -f "$ETC/sentinels.yaml" ]; then
  install -m 0640 -o root -g sentinels "$TMP/sentinels.example.yaml" "$ETC/sentinels.yaml"
  say "configuração criada: $ETC/sentinels.yaml"
else
  install -m 0640 -o root -g sentinels "$TMP/sentinels.example.yaml" "$ETC/sentinels.example.yaml"
  say "configuração existente mantida; exemplo atualizado em $ETC/sentinels.example.yaml"
fi
if [ ! -f "$ETC/sentinels.env" ]; then
  # Lido pelo systemd (root) antes de trocar de usuário: só root precisa ler.
  install -m 0600 -o root -g root "$TMP/sentinels.env.example" "$ETC/sentinels.env"
  say "arquivo de segredos criado: $ETC/sentinels.env (0600)"
fi

install -m 0644 "$TMP/sentinels.service" "$UNIT"
systemctl daemon-reload

# Assistente de configuração: lê do terminal mesmo com "curl … | sudo sh".
if [ "$SETUP" -ne 0 ] && (exec </dev/tty) 2>/dev/null; then
  printf '\nAbrir o assistente de configuração agora? [S/n] ' >/dev/tty
  read -r answer </dev/tty || answer=n
  case "$answer" in
    n|N|não|nao) ;;
    *) "$BIN" setup -config "$ETC/sentinels.yaml" </dev/tty >/dev/tty 2>&1 || warn "assistente encerrado; rode de novo com: sudo sentinels setup" ;;
  esac
fi

if [ "$START" -eq 1 ]; then
  systemctl enable --now sentinels.service
  say "serviço iniciado: journalctl -u sentinels -f"
fi

cat <<EOF

Sentinels instalado. Próximos passos:
  1. sudo sentinels setup              (assistente: IA, alertas, integrações, bancos)
  2. sudo -u sentinels sentinels doctor -config $ETC/sentinels.yaml
  3. sudo systemctl enable --now sentinels
  4. journalctl -u sentinels -f

Recomendado: Trivy para CVEs das imagens (https://trivy.dev) e CrowdSec para
ataques em tempo real (https://crowdsec.net). Veja docs/INSTALLATION.md.
EOF
