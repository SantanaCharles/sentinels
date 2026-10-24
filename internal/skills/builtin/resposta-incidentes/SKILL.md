---
name: resposta-incidentes
description: Primeiros passos de resposta quando há indício de comprometimento de um container ou servidor — conter, preservar evidências, erradicar e recuperar.
metadata:
  applies-to: "severity:critical, t1190, t1059, t1505.003, t1068, t1611, t1496, t1071, t1105, t1041"
---

# Resposta a incidentes (primeiras horas)

## Ordem de prioridade
1. **Conter sem destruir evidência.** Isole antes de apagar.
   - Container: `docker network disconnect <rede> <container>` ou `docker pause <container>`.
     Evite `docker rm` até copiar as evidências.
   - Bloqueie o IP de origem no firewall ou com o bouncer do CrowdSec.
2. **Preservar evidências** (somente leitura):
   - `docker logs --timestamps <container> > logs.txt`
   - `docker inspect <container> > inspect.json`
   - `docker diff <container>` mostra arquivos criados ou alterados no container.
   - `docker export <container> > fs.tar` para análise posterior.
   - Anote horários; guarde os relatórios e `sentinels events --since 48h`.
3. **Avaliar o alcance:** o container tinha segredos em variáveis de ambiente, acesso ao banco,
   ao socket do Docker ou à rede interna? Tudo que ele alcançava deve ser considerado exposto.
4. **Erradicar:** recrie o container a partir de imagem corrigida e limpa — nunca "limpe" um
   container comprometido. Corrija a vulnerabilidade que permitiu a entrada antes de voltar.
5. **Trocar credenciais** que o container conhecia: banco, APIs, tokens, chaves SSH.
6. **Recuperar e monitorar:** volte o serviço e acompanhe o mesmo alvo com atenção redobrada
   por alguns dias.

## Sinais de que a invasão avançou
- Shell interativo, downloads com curl/wget, processos de mineração (alto uso de CPU).
- Conexões de saída para IPs desconhecidos.
- Novos usuários, chaves SSH, cron jobs ou arquivos em diretórios web.

## Comunicação
Se dados pessoais podem ter sido acessados, a LGPD exige avaliar a comunicação à ANPD e aos
titulares (veja a skill lgpd-incidentes). Registre o incidente mesmo que conclua não comunicar.
