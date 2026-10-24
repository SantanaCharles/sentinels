---
name: php-seguranca
description: Segurança de aplicações PHP em container (WordPress, Moodle, Nextcloud, Laravel, GLPI) — atualização do runtime, configuração do php.ini e resposta a falhas críticas do núcleo como o PHP2Shell.
metadata:
  applies-to: "stack:php, advisory.php2shell*, cve.*"
---

# Segurança em aplicações PHP

## Falhas críticas do núcleo (ex.: PHP2Shell, out/2026)
CVE-2026-109618 e CVE-2026-109619: execução remota de código sem autenticação, afetando o PHP
desde a 5.4 em qualquer modo web (mod_php, PHP-FPM, php-cgi). Corrigido em **8.5.12, 8.4.27,
8.3.36 e 8.2.35**. Apache + mod_php é o cenário de maior risco.
- **A única correção é atualizar.** Configuração e WAF reduzem a exposição só parcialmente.
- 8.1 e anteriores não têm correção oficial: migre de versão.
- Pacotes de distribuição (Debian, Ubuntu, RHEL) recebem a correção sem mudar o número da
  versão — confira o aviso de segurança da distribuição.

## Como atualizar em container
- Imagem oficial `php:*`: troque a tag para a versão corrigida, reconstrua e recrie
  (`docker compose build --pull && docker compose up -d`).
- Imagens de aplicação (wordpress, nextcloud, moodle…): use uma tag publicada depois da
  correção; confira com `docker exec <container> php -v`.
- Imagens próprias: atualize o `FROM` e reconstrua sem cache.

## Configuração recomendada (php.ini)
```ini
expose_php = Off            ; remove X-Powered-By
display_errors = Off
log_errors = On
allow_url_include = Off
session.cookie_httponly = 1
session.cookie_secure = 1
session.use_strict_mode = 1
```
- `disable_functions` reduz o impacto de uma invasão, mas não substitui a atualização.
- Diretórios de upload não devem executar PHP (no Apache: `php_admin_flag engine off` no
  diretório; no Nginx: não encaminhar `uploads/*.php` ao FPM).

## Depois de uma possível exploração
Procure arquivos `.php` novos em diretórios de upload e cache (`docker diff <container>`),
tarefas agendadas novas e conexões de saída. Considere comprometidas as credenciais do
`wp-config.php`, `config.php` ou `.env` da aplicação.
