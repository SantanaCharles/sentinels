# Instalação

Duas formas, mesma funcionalidade. Na dúvida, use **Docker**: é a mais isolada.

## Opção A — Docker Compose (recomendada)

```bash
git clone https://github.com/SantanaCharles/sentinels && cd sentinels/deploy
cp sentinels.docker.yaml sentinels.yaml
cp sentinels.env.example sentinels.env && chmod 600 sentinels.env
docker compose up -d
docker compose exec sentinels sentinels doctor -config /etc/sentinels/sentinels.yaml
docker compose logs -f sentinels
```

- A imagem já traz o **Trivy**.
- O agente **não recebe o socket do Docker**: usa `tecnativa/docker-socket-proxy`, que só permite
  ler containers e imagens (qualquer `POST` recebe 403). Mesmo comprometido, o agente não cria
  containers nem controla o host.
- Roda como usuário 65532, sistema de arquivos somente leitura, sem capabilities, com
  `no-new-privileges` e limite de memória.
- `network_mode: host` é necessário para testar as portas publicadas em `127.0.0.1`, ver serviços
  escutando no host e receber o Falco em `127.0.0.1:2801`.
- Comandos: `docker compose exec sentinels sentinels <comando> -config /etc/sentinels/sentinels.yaml`.
- Assistente de configuração (grava `sentinels.yaml` e `sentinels.env` nesta pasta):

  ```bash
  docker run --rm -it --network host --user "$(id -u):$(id -g)" -v "$PWD:/work" \
    ghcr.io/santanacharles/sentinels:latest setup -config /work/sentinels.yaml -env /work/sentinels.env
  ```

  Depois, num comando separado (recria o container: `restart` não relê o `sentinels.env`):

  ```bash
  docker compose up -d --force-recreate sentinels
  ```

## Opção A2 — Portainer (stack)

1. **Stacks → Add stack**, nome `sentinels`, **Web editor**: cole o arquivo certo para o seu
   ambiente → **Deploy the stack**.

   | Ambiente no Portainer | Arquivo |
   |-----------------------|---------|
   | Docker Standalone | [`deploy/portainer-stack.yml`](../deploy/portainer-stack.yml) |
   | **Docker Swarm** (comum em VPS com Traefik, n8n, Evolution API) | [`deploy/portainer-stack-swarm.yml`](../deploy/portainer-stack-swarm.yml) |

   Se aparecer *"Compose file contains unsupported options: mem_limit"*, o ambiente é Swarm:
   use o segundo arquivo. Nele agente e proxy rodam em modo **global** (um por nó), na rede do
   host, e o proxy escuta só em `127.0.0.1` — no Swarm não use `ports` para o proxy, porque o
   Swarm ignora o `127.0.0.1` e publicaria a porta em todas as interfaces.
   (Também dá para usar **Repository**: URL `https://github.com/SantanaCharles/sentinels` e o
   caminho do arquivo — atualizações com "Pull and redeploy".)
2. **Containers → sentinels-sentinels-1 → Console** → *Command*: **Custom** →
   `/usr/local/bin/sentinels setup -config /var/lib/sentinels/sentinels.yaml` → deixe *User*
   vazio → **Connect**. Configure com as setas e escolha "Salvar e sair". Se o menu demorar a
   aparecer, use o mesmo comando com `--plain` (perguntas simples).
3. **Restart** no container `sentinels-sentinels-1` (Swarm: **Services → sentinels_sentinels →
   Update the service** com "Re-pull image" desmarcado) e acompanhe em **Logs**.

Sem arquivos no host: `sentinels.yaml` e `sentinels.env` (0600) ficam no volume
`sentinels-data`, e o agente lê o `.env` sozinho. Antes do passo 2 ele já roda com a
configuração padrão (varredura, CVEs, chaves vazadas; alertas só no log).

O próprio Portainer vai aparecer no relatório: ele monta o socket do Docker com escrita
(Crítico) e publica o painel (Alto). É o esperado para o Portainer — mantenha-o atualizado,
com senha forte/2FA e, de preferência, acessível só por VPN ou túnel SSH.

## Opção B — Binário + systemd

```bash
curl -fsSL https://github.com/SantanaCharles/sentinels/releases/latest/download/install.sh -o install.sh
less install.sh                     # leia antes de rodar como root
sudo sh install.sh
sudo nano /etc/sentinels/sentinels.yaml
sudo nano /etc/sentinels/sentinels.env
sudo -u sentinels sentinels doctor -config /etc/sentinels/sentinels.yaml
sudo systemctl enable --now sentinels
journalctl -u sentinels -f
```

No final, o instalador oferece abrir o **assistente** (`sentinels setup`) — funciona mesmo com
`curl … | sudo sh`, porque lê do terminal. Pule com `--no-setup`. Em consoles web de alguns
provedores o menu pode levar ~5 s para abrir (o console não responde a consultas do terminal);
`sentinels setup --plain` usa perguntas simples.

O instalador:
- confere o **SHA-256** de cada arquivo contra o `checksums.txt` da release e não instala nada se
  algo não conferir;
- cria o usuário de sistema `sentinels` e o adiciona apenas aos grupos que existem (`docker`,
  `adm`, `systemd-journal`);
- **não sobrescreve** `sentinels.yaml` nem `sentinels.env` existentes; `sentinels.env` fica 0600
  (só root — o systemd lê antes de trocar de usuário);
- **não inicia** o serviço (use `--start` se quiser).

O serviço roda com sandbox do systemd (`ProtectSystem=strict`, sem capabilities, filtro de
syscalls, só escreve em `/var/lib/sentinels`): `systemd-analyze security sentinels` → **1.7 OK**.

**Atenção:** estar no grupo `docker` equivale a root no host. Para isolar como no Docker
Compose, suba só o proxy e aponte o agente para ele:

```bash
docker run -d --name sentinels-socket-proxy --restart unless-stopped \
  -e CONTAINERS=1 -e IMAGES=1 -e POST=0 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro -p 127.0.0.1:2375:2375 \
  --label io.sentinels.self=true tecnativa/docker-socket-proxy:v0.5.0
sudo gpasswd -d sentinels docker
echo 'DOCKER_HOST=tcp://127.0.0.1:2375' | sudo tee -a /etc/sentinels/sentinels.env
sudo systemctl restart sentinels
```

Atualizar: rode o `install.sh` de novo. Remover: `sudo sh install.sh --uninstall`
(`--purge` apaga também configuração, memória e usuário).

### Trivy (CVEs das imagens)

```bash
# https://trivy.dev/latest/getting-started/installation/
sudo apt install trivy          # após adicionar o repositório oficial
```

## Primeira execução

A primeira varredura é a **linha de base**: você recebe um único resumo, não um alerta por achado.
Daí em diante chegam só novidades — e CVEs comuns são agrupadas por container; só CVEs
exploradas ativamente (CISA KEV) e alertas emergenciais chegam uma a uma.

CVEs de pacotes do kernel dentro das imagens (`linux-libc-dev`…) são desconsideradas: o container
usa o kernel do host. Mantenha o kernel do servidor atualizado.

## Feed de alertas emergenciais (mantenedores)

`internal/intel/advisories.json` é assinado com Ed25519. Depois de editar:

```bash
go run ./cmd/feedsign sign -key ~/.sentinels/feed-signing.key internal/intel/advisories.json
go run ./cmd/feedsign verify internal/intel/advisories.json
git add internal/intel/advisories.json internal/intel/advisories.json.sig
```

O CI falha se a assinatura não conferir. A chave privada nunca vai para o repositório
(`*.key` está no `.gitignore`).

### Rascunho com IA

```bash
go run ./cmd/feedsign draft -in https://www.cisa.gov/news-events/alerts/... -config sentinels.yaml -out rascunho.json
```

A IA lê o aviso e propõe a entrada do feed. O rascunho é validado: formato de cada campo, e
**toda CVE, versão corrigida e URL precisa aparecer no texto da fonte** (pega invenções da IA);
produtos que o agente ainda não detecta são apontados. Nada é incluído no feed nem assinado
automaticamente — revise, cole em `advisories.json` e rode `feedsign sign`.
