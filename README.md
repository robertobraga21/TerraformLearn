from kubernetes import client, config

def buscar_irsa_cluster():
    # 1. Configuração de Autenticação
    # Tenta carregar do arquivo local (~/.kube/config). 
    # Se estiver rodando dentro de um pod, use config.load_incluster_config()
    try:
        config.load_kube_config()
    except Exception as e:
        print(f"Erro ao carregar configuração do Kubernetes: {e}")
        return
        
    v1 = client.CoreV1Api()

    # 2. LISTA DE EXCLUSÃO (Edite aqui)
    # Namespaces que o script deve IGNORAR
    namespaces_ignorados = [
        "kube-system",
        "kube-public",
        "kube-node-lease",
        "monitoring",       # Exemplo de observabilidade
        "logging",          # Exemplo de observabilidade
        "istio-system",     # Exemplo de infraestrutura
        "amazon-cloudwatch"
    ]

    print(f"{'-'*60}")
    print(f"INICIANDO BUSCA POR IRSA (Excluindo: {len(namespaces_ignorados)} namespaces)")
    print(f"{'-'*60}")
    print(f"{'NAMESPACE':<25} | {'SERVICE ACCOUNT':<25} | {'IAM ROLE ARN'}")
    print(f"{'-'*120}")

    try:
        # 3. Busca todos os namespaces do cluster
        todos_namespaces = v1.list_namespace()

        for ns in todos_namespaces.items:
            ns_nome = ns.metadata.name

            # 4. Lógica de Filtragem
            if ns_nome in namespaces_ignorados:
                continue

            # Busca ServiceAccounts dentro do namespace atual
            service_accounts = v1.list_namespaced_service_account(ns_nome)

            for sa in service_accounts.items:
                annotations = sa.metadata.annotations
                
                # 5. Verificação da anotação de IRSA
                # A chave padrão para IRSA é 'eks.amazonaws.com/role-arn'
                if annotations and 'eks.amazonaws.com/role-arn' in annotations:
                    role_arn = annotations['eks.amazonaws.com/role-arn']
                    print(f"{ns_nome:<25} | {sa.metadata.name:<25} | {role_arn}")

    except Exception as e:
        print(f"\nOcorreu um erro durante a execução: {e}")

if __name__ == "__main__":
    buscar_irsa_cluster()
