# 1. Defina as variáveis (Simulando os parâmetros do Jenkins)
export ENV_TYPE="DEV"
export AWS_REGION="us-east-1"
export OPERATION_MODE="FULL_MIGRATION" # ou BACKUP_ONLY, RESTORE_ONLY

# Seus recursos (já devem existir)
export VELERO_BUCKET_NAME="velero-backup-dev-SUA_CONTA"
export VELERO_ROLE_ARN="arn:aws:iam::SUA_CONTA:role/velero-role-dev-auto"

# Seus Clusters
export CLUSTER_SOURCE_NAME="migrate-eks-origem-pxdu7DEz"
export CLUSTER_DEST_NAME="migrate-eks-destino-B7GvqvxU"

# IMPORTANTE: Seu profile local da AWS (~/.aws/credentials)
export AWS_PROFILE="default" 

# Opcionais
export ISTIO_SYNC_MODE="all"
export CLEANUP_ENABLED="true"

# 2. Roda o script
python3 migracao_jenkins.py
