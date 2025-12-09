#!/bin/bash

# ==========================================
# SIMULADOR DE PIPELINE (Teste Local)
# ==========================================

# 1. Configurações Básicas
export OPERATION_MODE="FULL_MIGRATION"       # FULL_MIGRATION, BACKUP_ONLY, RESTORE_ONLY
export AWS_REGION="us-east-1"
export AWS_PROFILE="default"                 # Seu profile local

# 2. Infraestrutura
export VELERO_BUCKET_NAME="velero-backup-dev-925774240266"
export VELERO_ROLE_ARN="arn:aws:iam::925774240266:role/velero-role-dev-auto"

# 3. Clusters
export CLUSTER_SOURCE_NAME="migrate-eks-origem-pxdu7DEz"
export CLUSTER_DEST_NAME="migrate-eks-destino-B7GvqvxU"

# 4. Opcionais
export ISTIO_SYNC_MODE="all"

# (Opcional) Apenas para RESTORE_ONLY
# export BACKUP_NAME_TO_RESTORE="migracao-1700000000"

echo "🚀 Rodando migração local..."
python3 -u migracao_jenkins.py
