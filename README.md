import boto3
import json
from kubernetes import client, config

# ================= CONFIGURAÇÕES =================
# O ID do OIDC do NOVO cluster (sem https://)
# Exemplo: "oidc.eks.us-west-1.amazonaws.com/id/EXAMPLED539D0..."
NOVO_OIDC_PROVIDER = "oidc.eks.REGION.amazonaws.com/id/XXXXXXXXXXXXXXXXXXXXXX"

NAMESPACES_IGNORADOS = [
    "kube-system", "kube-public", "monitoring", "logging", "amazon-cloudwatch"
]

# Modo DRY_RUN: Se True, apenas simula e mostra o que faria (mais seguro para testar)
DRY_RUN = True 
# =================================================

def obter_account_id():
    """Busca o ID da conta AWS atual para montar ARNs."""
    sts = boto3.client('sts')
    return sts.get_caller_identity().get('Account')

def atualizar_trust_policy(iam_client, role_name, namespace, service_account, account_id):
    try:
        # 1. Busca a policy atual
        role = iam_client.get_role(RoleName=role_name)
        policy_doc = role['Role']['AssumeRolePolicyDocument']
        
        # 2. Verifica se já existe a regra para evitar duplicidade
        str_policy = json.dumps(policy_doc)
        if NOVO_OIDC_PROVIDER in str_policy:
            print(f"  [SKIP] Role '{role_name}' já possui o novo OIDC configurado.")
            return

        print(f"  [UPDATE] Preparando atualização para Role: {role_name}...")

        # 3. Cria o novo Statement para o novo cluster
        novo_statement = {
            "Effect": "Allow",
            "Principal": {
                "Federated": f"arn:aws:iam::{account_id}:oidc-provider/{NOVO_OIDC_PROVIDER}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    f"{NOVO_OIDC_PROVIDER}:sub": f"system:serviceaccount:{namespace}:{service_account}",
                    f"{NOVO_OIDC_PROVIDER}:aud": "sts.amazonaws.com"
                }
            }
        }

        # 4. Adiciona ao documento existente
        policy_doc['Statement'].append(novo_statement)

        # 5. Aplica a mudança (se não for Dry Run)
        if not DRY_RUN:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(policy_doc)
            )
            print(f"  [SUCESSO] Trust Policy atualizada na AWS!")
        else:
            print(f"  [DRY-RUN] Simulação: Novo statement adicionado à lista. Nenhuma alteração feita na AWS.")

    except Exception as e:
        print(f"  [ERRO] Falha ao atualizar role {role_name}: {e}")

def main():
    # Config K8s
    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()
    except Exception as e:
        print(f"Erro K8s: {e}")
        return

    # Config AWS IAM
    try:
        iam = boto3.client('iam')
        account_id = obter_account_id()
        print(f"Logado na conta AWS: {account_id}")
    except Exception as e:
        print(f"Erro AWS: {e}. Verifique suas credenciais.")
        return

    print(f"--- Iniciando Migração de IRSA (DRY_RUN={DRY_RUN}) ---")

    todos_namespaces = v1.list_namespace()

    for ns in todos_namespaces.items:
        ns_nome = ns.metadata.name
        if ns_nome in NAMESPACES_IGNORADOS:
            continue

        service_accounts = v1.list_namespaced_service_account(ns_nome)
        for sa in service_accounts.items:
            annotations = sa.metadata.annotations
            
            if annotations and 'eks.amazonaws.com/role-arn' in annotations:
                role_arn = annotations['eks.amazonaws.com/role-arn']
                # Extrai apenas o nome da Role do ARN
                role_name = role_arn.split("/")[-1]
                sa_name = sa.metadata.name
                
                print(f"\nProcessando: NS={ns_nome} | SA={sa_name} | Role={role_name}")
                
                atualizar_trust_policy(iam, role_name, ns_nome, sa_name, account_id)

if __name__ == "__main__":
    main()
