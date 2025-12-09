#!/bin/bash

# ==========================================
# SIMULADOR DE PIPELINE (Teste Local)
# Preencha os dados abaixo antes de rodar.
# ==========================================

# --- 1. Configurações Gerais ---
export ENV_TYPE="DEV"                        # Opções: DEV, HML, PRD
export AWS_REGION="us-east-1"
export OPERATION_MODE="FULL_MIGRATION"       # Opções: FULL_MIGRATION, BACKUP_ONLY, RESTORE_ONLY

# --- 2. Autenticação (SSO Profile) ---
# Deve ser o nome exato do profile configurado no seu ~/.aws/config
export AWS_PROFILE="default"

# --- 3. Infraestrutura Velero (Já existentes) ---
export VELERO_BUCKET_NAME="nome-do-seu-bucket-velero"
export VELERO_ROLE_ARN="arn:aws:iam::123456789012:role/sua-role-velero"

# --- 4. Clusters EKS ---
export CLUSTER_SOURCE_NAME="nome-cluster-origem"  # Obrigatório para FULL e BACKUP
export CLUSTER_DEST_NAME="nome-cluster-destino"   # Obrigatório para FULL e RESTORE

# --- 5. Opcionais ---
export ISTIO_SYNC_MODE="all"                      # 'all', 'none' ou lista 'vs-app1,vs-app2'
export CLEANUP_ENABLED="true"                     # 'true' ou 'false'

# Apenas se OPERATION_MODE="RESTORE_ONLY"
# export BACKUP_NAME_TO_RESTORE="migracao-1700000000"

# ==========================================
# EXECUÇÃO
# ==========================================
echo "🚀 Iniciando automação local..."
echo "📂 Profile: $AWS_PROFILE | Modo: $OPERATION_MODE"

# O flag -u garante que o log saia em tempo real
python3 -u corp.py
