#!/bin/bash

# ---------------------------------------------------------------------------
# Script: vuln-redscan-turma07.sh
# Objetivo: Realizar análise básica de logs de acesso HTTP para identificar
#           possíveis indícios de ataques como XSS, SQL Injection, Scanners,
#           acesso a arquivos sensíveis e outras atividades suspeitas.
# Autor: domcabral9
# Contato: domcabral@proton.me
# ---------------------------------------------------------------------------

# Diretório de logs
LOG_DIR="logs"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOG_DIR/scan-$TIMESTAMP.log"

# Verifica se o diretório existe
if [ ! -d "$LOG_DIR" ]; then
    mkdir "$LOG_DIR"
fi

printf "\n[+] Etapa 1 - Detectar possíveis ataques de XSS (Cross-Site Scripting)\n" | tee -a "$LOG_FILE"
grep -iE "<script|%3Cscript" access.log | tee -a "$LOG_FILE"

printf "\n[+] Etapa 2 - Detectar tentativas de SQL Injection\n" | tee -a "$LOG_FILE"
grep -iE "union|select|insert|drop|%27|%22" access.log | tee -a "$LOG_FILE"

printf "\n[+] Etapa 3 - Detectar varredura de diretórios (Directory Traversal)\n" | tee -a "$LOG_FILE"
grep -E "\.\./|\.\.%2f" access.log | tee -a "$LOG_FILE"

printf "\n[+] Etapa 4 - Detectar possíveis ataques por scanners (User-Agent suspeito)\n" | tee -a "$LOG_FILE"
grep -iE "nikto|nmap|sqlmap|acunetix|curl|masscan|python" access.log | tee -a "$LOG_FILE"

printf "\n[+] Etapa 5 - Identificar tentativas de acesso a arquivos sensíveis (.env, .git, etc.)\n" | tee -a "$LOG_FILE"
grep -iE "\.env|\.git|\.htaccess|\.bak" access.log | tee -a "$LOG_FILE"

printf "\n[+] Etapa 6 - Detectar possíveis ataques de força bruta a arquivos/pastas\n" | tee -a "$LOG_FILE"
grep " 404 " access.log | cut -d " " -f 1 | sort | uniq -c | sort -nr | head | tee -a "$LOG_FILE"

printf "\n[+] Etapa 7 - Primeiro e último acesso de um IP suspeito\n" | tee -a "$LOG_FILE"
grep "IP" access.log | head -n1 | tee -a "$LOG_FILE"
grep "IP" access.log | tail -n1 | tee -a "$LOG_FILE"
=
printf "\n[+] Etapa 8 - Localizar user-agent utilizado por um IP suspeito\n" | tee -a "$LOG_FILE"
grep "IP_SUSPEITO" access.log | cut -d '"' -f 6 | sort | uniq | tee -a "$LOG_FILE"

printf "\n[+] Etapa 9 - Listar os IPs e verificar o número de requisições\n" | tee -a "$LOG_FILE"
cat access.log | cut -d " " -f 1 | sort | uniq -c | tee -a "$LOG_FILE"

printf "\n[+] Etapa 10 - Localizar acesso a um determinado arquivo sensível\n" | tee -a "$LOG_FILE"
grep "arquivosensivel" access.log | tee -a "$LOG_FILE"

printf "\n[✔] Análise concluída. Resultados salvos em $LOG_FILE\n"
exit 0
