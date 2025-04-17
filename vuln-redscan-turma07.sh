#!/bin/bash

# ---------------------------------------------------------------------------
# Script: vuln-redscan-turma07-v2.sh
# Objetivo: Menu interativo para análise de logs HTTP com foco em cibersegurança
# Autor: domcabral9
# Contato: domcabral@proton.me
# ---------------------------------------------------------------------------

# Cores
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

# Verifica se argumento de arquivo foi passado
if [[ "$1" != "--arquivo" || -z "$2" ]]; then
    echo -e "${RED}[!] Uso correto: $0 --arquivo <caminho_para_log>${RESET}"
    exit 1
fi

ARQUIVO_LOG="$2"

if [ ! -f "$ARQUIVO_LOG" ]; then
    echo -e "${RED}[!] Arquivo '$ARQUIVO_LOG' não encontrado.${RESET}"
    exit 1
fi

# Cria diretório de logs
LOG_DIR="logs"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOG_DIR/scan-$TIMESTAMP.log"
mkdir -p "$LOG_DIR"

read -rp $'\e[33mDigite o IP suspeito para análise: \e[0m' SUSPECT_IP
if [[ ! $SUSPECT_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo -e "${RED}[!] IP inválido. Encerrando...${RESET}"
    exit 1
fi

read -rp $'\e[33mDigite o nome de um arquivo sensível para busca (ex: .env): \e[0m' SENSITIVE_FILE

while true; do
    echo ""
    echo -e "${CYAN}Selecione a etapa de análise:${RESET}"
    echo "1) Detectar XSS"
    echo "2) Detectar SQL Injection"
    echo "3) Directory Traversal"
    echo "4) Scanners suspeitos"
    echo "5) Arquivos sensíveis"
    echo "6) Força bruta (404)"
    echo "7) Primeiro e último acesso de IP"
    echo "8) User-Agent de IP"
    echo "9) Requisições por IP"
    echo "10) Acesso a arquivo sensível"
    echo "0) Sair"
    read -rp $'\e[33mOpção: \e[0m' opt

    case $opt in
        1)
            echo -e "\n${CYAN}[+] XSS${RESET}" | tee -a "$LOG_FILE"
            grep -iE "<script|%3Cscript" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        2)
            echo -e "\n${CYAN}[+] SQL Injection${RESET}" | tee -a "$LOG_FILE"
            grep -iE "union|select|insert|drop|%27|%22" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        3)
            echo -e "\n${CYAN}[+] Directory Traversal${RESET}" | tee -a "$LOG_FILE"
            grep -E "\.\./|\.\.%2f" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        4)
            echo -e "\n${CYAN}[+] Scanners suspeitos${RESET}" | tee -a "$LOG_FILE"
            grep -iE "nikto|nmap|sqlmap|acunetix|curl|masscan|python" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        5)
            echo -e "\n${CYAN}[+] Arquivos sensíveis${RESET}" | tee -a "$LOG_FILE"
            grep -iE "\.env|\.git|\.htaccess|\.bak" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        6)
            echo -e "\n${CYAN}[+] Força bruta (404)${RESET}" | tee -a "$LOG_FILE"
            grep " 404 " "$ARQUIVO_LOG" | cut -d " " -f 1 | sort | uniq -c | sort -nr | head | tee -a "$LOG_FILE"
            ;;
        7)
            echo -e "\n${CYAN}[+] Primeiro e último acesso do IP $SUSPECT_IP${RESET}" | tee -a "$LOG_FILE"
            grep "$SUSPECT_IP" "$ARQUIVO_LOG" | head -n1 | tee -a "$LOG_FILE"
            grep "$SUSPECT_IP" "$ARQUIVO_LOG" | tail -n1 | tee -a "$LOG_FILE"
            ;;
        8)
            echo -e "\n${CYAN}[+] User-Agent de $SUSPECT_IP${RESET}" | tee -a "$LOG_FILE"
            grep "$SUSPECT_IP" "$ARQUIVO_LOG" | cut -d '"' -f 6 | sort | uniq | tee -a "$LOG_FILE"
            ;;
        9)
            echo -e "\n${CYAN}[+] Requisições por IP${RESET}" | tee -a "$LOG_FILE"
            cut -d " " -f 1 "$ARQUIVO_LOG" | sort | uniq -c | tee -a "$LOG_FILE"
            ;;
        10)
            echo -e "\n${CYAN}[+] Acessos ao arquivo '$SENSITIVE_FILE'${RESET}" | tee -a "$LOG_FILE"
            grep "$SENSITIVE_FILE" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        0)
            echo -e "${GREEN}[✔] Saindo. Log salvo em $LOG_FILE${RESET}"
            exit 0
            ;;
        *)
            echo -e "${RED}[!] Opção inválida.${RESET}"
            ;;
    esac

done
