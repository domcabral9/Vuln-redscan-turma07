#!/bin/bash

# ---------------------------------------------------------------------------
# Script: vuln-redscan-turma07.sh
# Objetivo: Menu interativo para análise de logs HTTP com foco em cibersegurança
# Autor: domcabral9
# Contato: domcabral@proton.me
# Revisão 0.2
# ---------------------------------------------------------------------------

# Cores
VERMELHO="\e[31m"
VERDE="\e[32m"
AMARELO="\e[33m"
CIANO="\e[36m"
RESETA_COR="\e[0m"

# Verifica se argumento de arquivo foi passado
if [[ "$1" != "--arquivo" || -z "$2" ]]; then
    echo -e "${VERMELHO}[!] Uso correto: $0 --arquivo <caminho_para_log>${RESETA_COR}"
    exit 1
fi

ARQUIVO_LOG="$2"

if [ ! -f "$ARQUIVO_LOG" ]; then
    echo -e "${VERMELHO}[!] Arquivo '$ARQUIVO_LOG' não encontrado.${RESETA_COR}"
    exit 1
fi

# Cria diretório de logs
LOG_DIR="logs"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOG_DIR/scan-$TIMESTAMP.log"
mkdir -p "$LOG_DIR"

read -rp $'\e[33mDigite o IP suspeito para análise: \e[0m' IP_SUSPEITO
if [[ ! $IP_SUSPEITO =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo -e "${VERMELHO}[!] IP inválido. Encerrando...${RESETA_COR}"
    exit 1
fi

read -rp $'\e[33mDigite o nome de um arquivo sensível para busca (ex: .env): \e[0m' ARQUIVO_SENSIVEL

while true; do
    echo ""
    echo -e "${CIANO}Selecione a etapa de análise:${RESETA_COR}"
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
    read -rp $'\e[33mOpção: \e[0m' OPCAO

    case $OPCAO in
        1)
            echo -e "\n${CIANO}[+] XSS${RESETA_COR}" | tee -a "$LOG_FILE"
            grep -iE "<script|%3Cscript" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        2)
            echo -e "\n${CIANO}[+] SQL Injection${RESETA_COR}" | tee -a "$LOG_FILE"
            grep -iE "union|select|insert|drop|%27|%22" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        3)
            echo -e "\n${CIANO}[+] Directory Traversal${RESETA_COR}" | tee -a "$LOG_FILE"
            grep -E "\.\./|\.\.%2f" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        4)
            echo -e "\n${CIANO}[+] Scanners suspeitos${RESETA_COR}" | tee -a "$LOG_FILE"
            grep -iE "nikto|nmap|sqlmap|acunetix|curl|masscan|python" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        5)
            echo -e "\n${CIANO}[+] Arquivos sensíveis${RESETA_COR}" | tee -a "$LOG_FILE"
            grep -iE "\.env|\.git|\.htaccess|\.bak" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        6)
            echo -e "\n${CIANO}[+] Força bruta (404)${RESETA_COR}" | tee -a "$LOG_FILE"
            grep " 404 " "$ARQUIVO_LOG" | cut -d " " -f 1 | sort | uniq -c | sort -nr | head | tee -a "$LOG_FILE"
            ;;
        7)
            echo -e "\n${CIANO}[+] Primeiro e último acesso do IP $IP_SUSPEITO${RESETA_COR}" | tee -a "$LOG_FILE"
            grep "$IP_SUSPEITO" "$ARQUIVO_LOG" | head -n1 | tee -a "$LOG_FILE"
            grep "$IP_SUSPEITO" "$ARQUIVO_LOG" | tail -n1 | tee -a "$LOG_FILE"
            ;;
        8)
            echo -e "\n${CIANO}[+] User-Agent de $IP_SUSPEITO${RESETA_COR}" | tee -a "$LOG_FILE"
            grep "$IP_SUSPEITO" "$ARQUIVO_LOG" | cut -d '"' -f 6 | sort | uniq | tee -a "$LOG_FILE"
            ;;
        9)
            echo -e "\n${CIANO}[+] Requisições por IP${RESETA_COR}" | tee -a "$LOG_FILE"
            cut -d " " -f 1 "$ARQUIVO_LOG" | sort | uniq -c | tee -a "$LOG_FILE"
            ;;
        10)
            echo -e "\n${CIANO}[+] Acessos ao arquivo '$ARQUIVO_SENSIVEL'${RESETA_COR}" | tee -a "$LOG_FILE"
            grep "$ARQUIVO_SENSIVEL" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        0)
            echo -e "${VERDE}[✔] Saindo. Log salvo em $LOG_FILE${RESETA_COR}"
            exit 0
            ;;
        *)
            echo -e "${VERMELHO}[!] Opção inválida.${RESETA_COR}"
            ;;
    esac

done
