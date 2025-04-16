#!/bin/bash

# ---------------------------------------------------------------------------
# Script: vuln-redscan-turma07-v2.sh
# Objetivo: Menu interativo para análise de logs HTTP com foco em cibersegurança
# Autor: domcabral9
# Contato: domcabral@proton.me
# ---------------------------------------------------------------------------

# Verifica se argumento de arquivo foi passado
if [[ "$1" != "--arquivo" || -z "$2" ]]; then
    echo "Uso correto: $0 --arquivo <caminho_para_log>"
    exit 1
fi

ARQUIVO_LOG="$2"

if [ ! -f "$ARQUIVO_LOG" ]; then
    echo "[!] Arquivo '$ARQUIVO_LOG' não encontrado."
    exit 1
fi

# Cria diretório de logs
LOG_DIR="logs"
TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
LOG_FILE="$LOG_DIR/scan-$TIMESTAMP.log"
mkdir -p "$LOG_DIR"

read -rp "Digite o IP suspeito para análise: " SUSPECT_IP
if [[ ! $SUSPECT_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "[!] IP inválido. Encerrando..."
    exit 1
fi

read -rp "Digite o nome de um arquivo sensível para busca (ex: .env): " SENSITIVE_FILE

while true; do
    echo ""
    echo "Selecione a etapa de análise:"
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
    read -rp "Opção: " opt

    case $opt in
        1)
            printf "\n[+] XSS\n" | tee -a "$LOG_FILE"
            grep -iE "<script|%3Cscript" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        2)
            printf "\n[+] SQL Injection\n" | tee -a "$LOG_FILE"
            grep -iE "union|select|insert|drop|%27|%22" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        3)
            printf "\n[+] Directory Traversal\n" | tee -a "$LOG_FILE"
            grep -E "\.\./|\.\.%2f" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        4)
            printf "\n[+] Scanners suspeitos\n" | tee -a "$LOG_FILE"
            grep -iE "nikto|nmap|sqlmap|acunetix|curl|masscan|python" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        5)
            printf "\n[+] Arquivos sensíveis\n" | tee -a "$LOG_FILE"
            grep -iE "\.env|\.git|\.htaccess|\.bak" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        6)
            printf "\n[+] Força bruta (404)\n" | tee -a "$LOG_FILE"
            grep " 404 " "$ARQUIVO_LOG" | cut -d " " -f 1 | sort | uniq -c | sort -nr | head | tee -a "$LOG_FILE"
            ;;
        7)
            printf "\n[+] Primeiro e último acesso do IP $SUSPECT_IP\n" | tee -a "$LOG_FILE"
            grep "$SUSPECT_IP" "$ARQUIVO_LOG" | head -n1 | tee -a "$LOG_FILE"
            grep "$SUSPECT_IP" "$ARQUIVO_LOG" | tail -n1 | tee -a "$LOG_FILE"
            ;;
        8)
            printf "\n[+] User-Agent de $SUSPECT_IP\n" | tee -a "$LOG_FILE"
            grep "$SUSPECT_IP" "$ARQUIVO_LOG" | cut -d '"' -f 6 | sort | uniq | tee -a "$LOG_FILE"
            ;;
        9)
            printf "\n[+] Requisições por IP\n" | tee -a "$LOG_FILE"
            cut -d " " -f 1 "$ARQUIVO_LOG" | sort | uniq -c | tee -a "$LOG_FILE"
            ;;
        10)
            printf "\n[+] Acessos ao arquivo '$SENSITIVE_FILE'\n" | tee -a "$LOG_FILE"
            grep "$SENSITIVE_FILE" "$ARQUIVO_LOG" | tee -a "$LOG_FILE"
            ;;
        0)
            echo "[✔] Saindo. Log salvo em $LOG_FILE"
            exit 0
            ;;
        *)
            echo "[!] Opção inválida."
            ;;
    esac

done
