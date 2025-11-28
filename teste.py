import boto3
import json
import sys
from kubernetes import client, config
from botocore.exceptions import ProfileNotFound, NoCredentialsError, ClientError

# --- CONFIGURAÇÃO ESTÁTICA (Filtros de Namespace) ---
NAMESPACES_IGNORADOS = [
    "kube-system", 
    "kube-public", 
    "kube-node-lease", 
    "monitoring", 
    "logging", 
    "amazon-cloudwatch"
]

def obter_inputs_usuario():
    print(f"{'='*60}")
    print(f"{' MIGRATION WIZARD: IRSA TRUST RELATIONSHIP ':.^60}")
    print(f"{'='*60}")
    
    # 1. Profile
    profile = input("\n[1] Digite o nome do seu AWS PROFILE (conforme ~/.aws/credentials): ").strip()
    if not profile:
        print("❌ O nome do perfil é obrigatório.")
        sys.exit(1)

    # 2. Região
    region = input("[2] Digite a Região AWS (Padrão: us-east-1): ").strip()
    if not region:
        region = "us-east-1"

    # 3. OIDC
    print("\n[3] Cole o OIDC Provider do NOVO cluster (sem 'https://')")
    print("    Ex: oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D0...")
    novo_oidc = input("    > ").strip()
    # Remove https:// se o usuário colar por acidente
    novo_oidc = novo_oidc.replace("https://", "")
    
    if not novo_oidc:
        print("❌ O OIDC é obrigatório.")
        sys.exit(1)

    # 4. Modo de Execução
    print("\n[4] Modo de Execução:")
    print("    (S) Simulação / Dry-Run (Apenas lista o que faria)")
    print("    (E) Executar / Apply (Aplica as mudanças na AWS)")
    modo = input("    Escolha [S/E]: ").strip().upper()
    
    dry_run = True
    if modo == 'E':
        confirmacao = input("    ⚠️  TEM CERTEZA? Isso alterará as Roles na AWS. Digite 'SIM' para confirmar: ")
        if confirmacao == 'SIM':
            dry_run = False
        else:
            print("    Cancelado pelo usuário. Voltando para modo Simulação.")
    
    return profile, region, novo_oidc, dry_run

def atualizar_trust_policy(iam_client, role_name, namespace, service_account, account_id, novo_oidc, dry_run):
    try:
        role = iam_client.get_role(RoleName=role_name)
        policy_doc = role['Role']['AssumeRolePolicyDocument']
        
        # Verifica duplicidade
        str_policy = json.dumps(policy_doc)
        if novo_oidc in str_policy:
            print(f"  [SKIP] Role '{role_name}' já possui este OIDC.")
            return

        print(f"  [UPDATE] Adicionando novo OIDC na Role: {role_name}")

        novo_statement = {
            "Effect": "Allow",
            "Principal": {
                "Federated": f"arn:aws:iam::{account_id}:oidc-provider/{novo_oidc}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    f"{novo_oidc}:sub": f"system:serviceaccount:{namespace}:{service_account}",
                    f"{novo_oidc}:aud": "sts.amazonaws.com"
                }
            }
        }

        policy_doc['Statement'].append(novo_statement)

        if not dry_run:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(policy_doc)
            )
            print(f"  [SUCESSO] Policy atualizada na AWS!")
        else:
            print(f"  [DRY-RUN] Simulação: Statement preparado, mas não enviado.")

    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"  [ERRO] A Role '{role_name}' não foi encontrada na conta {account_id}.")
        else:
            print(f"  [ERRO] Falha AWS: {e}")
    except Exception as e:
        print(f"  [ERRO] Genérico: {e}")

def main():
    # Coleta dados via input
    aws_profile, aws_region, novo_oidc, dry_run = obter_inputs_usuario()

    # Configura Sessão AWS
    try:
        print(f"\n🔄 Conectando na AWS (Profile: {aws_profile} | Region: {aws_region})...")
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        iam = session.client('iam')
        sts = session.client('sts')
        
        identity = sts.get_caller_identity()
        account_id = identity.get('Account')
        print(f"✅ Conectado! Conta AWS: {account_id}")
        
    except ProfileNotFound:
        print(f"❌ Erro: O perfil '{aws_profile}' não foi encontrado no seu ~/.aws/config ou credentials.")
        return
    except NoCredentialsError:
        print("❌ Erro: Nenhuma credencial encontrada.")
        return
    except Exception as e:
        print(f"❌ Erro ao conectar na AWS: {e}")
        return

    # Configura Kubernetes
    print("\n🔄 Lendo contexto do Kubernetes...")
    try:
        config.load_kube_config()
        v1 = client.CoreV1Api()
        current_context = config.list_kube_config_contexts()[1]['name'] # Pega contexto atual
        print(f"✅ K8s conectado! Contexto atual: {current_context}")
    except Exception as e:
        print(f"❌ Erro ao conectar no Kubernetes: {e}")
        return

    print(f"\n{' INICIANDO VARREDURA ':=^60}")
    
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
                role_name = role_arn.split("/")[-1]
                sa_name = sa.metadata.name
                
                print(f"\n🔍 Encontrado: NS={ns_nome} | SA={sa_name}")
                atualizar_trust_policy(iam, role_name, ns_nome, sa_name, account_id, novo_oidc, dry_run)

    print(f"\n{' FIM DA EXECUÇÃO ':=^60}")

if __name__ == "__main__":
    main()
