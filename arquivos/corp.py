import subprocess
import time
import sys
import os
import json
import shutil
import boto3
from botocore.exceptions import ClientError, ProfileNotFound
from kubernetes import client, config as k8s_config

# --- CONFIGURAÇÃO GLOBAL ---
GLOBAL_SESSION = None # Será preenchida após login
CONFIG = {}

SYSTEM_NAMESPACES = [
    "default", "kube-system", "kube-public", "kube-node-lease", 
    "velero", "amazon-cloudwatch", "aws-observability", "istio-system", "istio-ingress", "cert-manager", "monitoring",
    "cattle-system", "cattle-fleet-system"
]

EXCLUDE_RESOURCES = "pods,replicasets,endpoints,endpointslices"

# --- 0. UI HELPERS ---
def print_step(msg): print(f"\n🔹 {msg}")
def print_success(msg): print(f"   ✅ {msg}")
def print_error(msg): print(f"   ❌ {msg}")
def print_info(msg): print(f"   ℹ️  {msg}")

def run_shell(cmd, ignore_error=False, quiet=True):
    # Se não for quiet, imprime o comando
    if not quiet: print(f"   [CMD] {cmd}")
    try: 
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL if quiet else None, stderr=subprocess.PIPE if quiet else None)
        return True
    except subprocess.CalledProcessError as e:
        if not ignore_error: 
            # Decodifica o erro para mostrar pro usuário se falhar
            err_msg = e.stderr.decode().strip() if e.stderr else "Erro desconhecido"
            print_error(f"Falha no comando shell: {err_msg}")
            # sys.exit(1) # Opcional: abortar ou retornar False
        return False

# --- 1. AWS AUTH & VALIDATION (CORE) ---

def select_aws_profile():
    print_step("Autenticação AWS")
    
    # Lista perfis disponíveis
    available_profiles = boto3.Session().available_profiles
    
    # Adiciona opção de variáveis de ambiente (Default/None)
    options = ["(Ambiente/Default)"] + sorted(available_profiles)
    
    print("   Perfis encontrados:")
    for idx, prof in enumerate(options):
        print(f"   [{idx}] {prof}")
    
    selected_profile = None
    
    while True:
        choice = input("\n   Selecione o número do perfil: ").strip()
        if not choice.isdigit():
            print_error("Digite um número válido.")
            continue
        
        choice = int(choice)
        if 0 <= choice < len(options):
            if choice == 0:
                selected_profile = None # Usa env vars
            else:
                selected_profile = options[choice]
            break
        else:
            print_error("Opção inválida.")

    # Teste de Login Imediato
    print_info(f"Testando credenciais para: {selected_profile if selected_profile else 'ENV_VARS'}...")
    try:
        session = boto3.Session(profile_name=selected_profile)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        print_success(f"Logado como: {identity['Arn']}")
        return session, selected_profile
    except Exception as e:
        print_error(f"Falha ao autenticar: {e}")
        print_info("Verifique suas credenciais ou MFA e tente novamente.")
        sys.exit(1)

def select_aws_region(session):
    print_step("Seleção de Região")
    default_region = "us-east-1"
    
    # Obtém regiões válidas para EC2
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        valid_regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    except:
        # Fallback se não der pra listar (permissão restrita), usa lista hardcoded comum
        valid_regions = ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "sa-east-1", "eu-central-1", "eu-west-1"]

    while True:
        region = input(f"   Região AWS [{default_region}]: ").strip()
        if not region: 
            region = default_region
        
        if region in valid_regions:
            # Atualiza a sessão global com a região correta
            CONFIG['region'] = region
            print_success(f"Região definida: {region}")
            # Retorna uma nova sessão travada na região correta
            if CONFIG['aws_profile']:
                return boto3.Session(profile_name=CONFIG['aws_profile'], region_name=region)
            else:
                return boto3.Session(region_name=region)
        else:
            print_error(f"Região '{region}' inválida ou inacessível.")
            print_info(f"Regiões comuns: {', '.join(valid_regions[:5])}...")

def validate_cluster_access(session, cluster_name):
    print_info(f"Validando acesso ao cluster '{cluster_name}'...")
    
    # 1. Valida existência na AWS
    eks = session.client('eks')
    try:
        cluster_info = eks.describe_cluster(name=cluster_name)
        arn = cluster_info['cluster']['arn']
        print_success("Cluster encontrado na AWS.")
    except ClientError:
        print_error(f"Cluster '{cluster_name}' não encontrado nesta região/conta.")
        return None

    # 2. Atualiza Kubeconfig
    print_info("Atualizando kubeconfig...")
    profile_flag = f"--profile {CONFIG['aws_profile']}" if CONFIG['aws_profile'] else ""
    cmd = f"aws eks update-kubeconfig --name {cluster_name} --region {CONFIG['region']} {profile_flag}"
    
    if not run_shell(cmd):
        print_error("Falha ao rodar 'aws eks update-kubeconfig'.")
        return None

    # 3. Teste real de API Kubernetes
    try:
        # Carrega config recém atualizada
        k8s_config.load_kube_config()
        # Tenta listar namespaces para provar acesso
        v1 = client.CoreV1Api()
        v1.list_namespace(limit=1)
        print_success("Conexão API Kubernetes confirmada!")
        return arn
    except Exception as e:
        print_error(f"Falha de conexão K8s: {e}")
        return None

def get_valid_input(prompt, validation_func, session=None):
    """Loop genérico de input + validação"""
    while True:
        val = input(f"   {prompt}: ").strip()
        if not val:
            print_error("Campo obrigatório.")
            continue
        
        # Se tiver função de validação, executa
        if validation_func:
            result = validation_func(session, val) if session else validation_func(val)
            if result:
                return val
        else:
            return val

# --- 2. VALIDADORES ESPECÍFICOS ---

def check_bucket(session, bucket_name):
    s3 = session.client('s3')
    try:
        s3.head_bucket(Bucket=bucket_name)
        print_success("Bucket válido e acessível.")
        return True
    except ClientError as e:
        err = e.response['Error']['Code']
        if err == '404': print_error("Bucket não existe.")
        elif err == '403': print_error("Sem permissão de acesso ao Bucket.")
        else: print_error(f"Erro no Bucket: {e}")
        return False

def check_role(session, role_arn):
    iam = session.client('iam')
    try:
        role_name = role_arn.split('/')[-1]
        iam.get_role(RoleName=role_name)
        print_success("Role IAM válida.")
        return True
    except Exception:
        print_error("Role inexistente ou sem permissão de leitura.")
        return False

def check_cluster_wrapper(session, cluster_name):
    # Wrapper para retornar True/False para o loop de input
    res = validate_cluster_access(session, cluster_name)
    return res is not None

# --- 3. VELERO & LOGICA (Adaptado para usar GLOBAL_SESSION) ---

def generate_velero_values(bucket, role_arn, region):
    print_info("Gerando 'values.yaml'...")
    yaml_content = f"""configuration:
  backupStorageLocation:
    - bucket: {bucket}
      prefix: velero
      provider: aws
      config:
        region: {region}
  volumeSnapshotLocation:
    - provider: aws
      config:
        region: {region}
credentials:
  useSecret: false
initContainers:
  - name: velero-plugin-for-aws
    image: velero/velero-plugin-for-aws:v1.9.0
    volumeMounts:
      - mountPath: /target
        name: plugins
serviceAccount:
  server:
    create: true
    name: velero-server
    annotations:
      eks.amazonaws.com/role-arn: {role_arn}
kubectl:
  image:
    repository: docker.io/bitnamilegacy/kubectl
upgradeCRDs: false
cleanUpCRDs: false
"""
    try:
        with open("values.yaml", "w") as f: f.write(yaml_content)
    except Exception as e: print_error(f"Erro escrevendo yaml: {e}"); sys.exit(1)

def get_cluster_oidc(cluster_name):
    # Usa a sessão global
    return GLOBAL_SESSION.client('eks').describe_cluster(name=cluster_name)['cluster']['identity']['oidc']['issuer'].replace("https://", "")

def configure_irsa_trust(role_arn, oidcs_list, ns, sa, mode='append'):
    role_name = role_arn.split('/')[-1]
    iam = GLOBAL_SESSION.client('iam')
    sts = GLOBAL_SESSION.client('sts')
    acc = sts.get_caller_identity()["Account"]
    
    try:
        current_policy = iam.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
        
        if mode == 'replace':
            new_statements = [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acc}:root"}, "Action": "sts:AssumeRole"}]
        else:
            new_statements = current_policy.get('Statement', [])

        unique_oidcs = list(set(oidcs_list))
        updated = False

        for oidc in unique_oidcs:
            oidc_arn = f"arn:aws:iam::{acc}:oidc-provider/{oidc}"
            exists = False
            
            # Checa se já existe a permissão com as condições corretas
            for s in new_statements:
                if s.get('Principal', {}).get('Federated') == oidc_arn:
                    cond = s.get('Condition', {}).get('StringEquals', {})
                    if (cond.get(f"{oidc}:sub") == f"system:serviceaccount:{ns}:{sa}" and 
                        cond.get(f"{oidc}:aud") == "sts.amazonaws.com"):
                        exists = True
                        break
            
            if not exists:
                new_statements.append({
                    "Effect": "Allow",
                    "Principal": {"Federated": oidc_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            f"{oidc}:sub": f"system:serviceaccount:{ns}:{sa}",
                            f"{oidc}:aud": "sts.amazonaws.com"
                        }
                    }
                })
                updated = True
        
        if updated or mode == 'replace':
            policy_doc = {"Version": "2012-10-17", "Statement": new_statements}
            iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(policy_doc))
            print_success(f"Trust Policy atualizada na role {role_name}.")
            return True
        return False
    except Exception as e:
        print_error(f"Erro Trust Policy: {e}")
        return False

# --- 4. FUNÇÕES DE SYNC/BACKUP ---
# (Mantive a lógica anterior, apenas ajustando prints e chamadas de shell)

def check_bsl_health():
    try:
        res = subprocess.run("kubectl get bsl default -n velero -o json", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.returncode != 0: return False, "BSL Missing"
        data = json.loads(res.stdout)
        phase = data.get('status', {}).get('phase', 'Unknown')
        if phase == 'Available': return True, "OK"
        return False, f"Status: {phase}"
    except: return False, "Erro API K8s"

def wait_for_backup_sync(bk):
    print_info(f"Aguardando sync do backup '{bk}' no destino...")
    for i in range(60): 
        healthy, msg = check_bsl_health()
        if not healthy:
            print_error(f"Velero Unhealthy: {msg}. Abortando."); return False
        
        # Verifica se o backup já aparece no cluster destino
        res = subprocess.run(f"velero backup describe {bk}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0: 
            print_success("Backup sincronizado e visível!")
            return True
        
        if i % 5 == 0: sys.stdout.write("."); sys.stdout.flush()
        time.sleep(5)
    print_error("Timeout aguardando sync do backup.")
    return False

def install_velero(context):
    print_step(f"Instalando Velero no contexto: {context}")
    
    # Switch context via shell para garantir que comandos helm/kubectl peguem o certo
    # (Embora update-kubeconfig já tenha feito isso, é bom garantir)
    run_shell(f"kubectl config use-context {context}", quiet=True)
    
    # Limpeza Hardcore
    run_shell("helm uninstall velero -n velero", ignore_error=True)
    run_shell("kubectl delete ns velero --timeout=10s --wait=false", ignore_error=True)
    time.sleep(5)
    
    # Instalação
    run_shell("kubectl create ns velero --dry-run=client -o yaml | kubectl apply -f -")
    run_shell("helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts", ignore_error=True)
    
    cmd = "helm upgrade --install velero vmware-tanzu/velero --namespace velero -f values.yaml --reset-values --wait"
    if not run_shell(cmd):
        print_error("Falha na instalação Helm. Tentando forçar...")
        run_shell(cmd) # Retries once
    
    print_success("Velero instalado.")

def backup_istio_to_s3(src_cluster, backup_name):
    print_step("Backup Istio (VirtualServices)")
    # Troca contexto apenas para garantir
    validate_cluster_access(GLOBAL_SESSION, src_cluster) 
    
    custom_api = client.CustomObjectsApi()
    s3 = GLOBAL_SESSION.client('s3')
    
    try:
        resp = custom_api.list_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices")
        items = resp.get('items', [])
    except Exception as e: 
        print_error(f"Erro lendo Istio (pode não estar instalado?): {e}")
        return

    tmp_dir = f"istio_tmp_{backup_name}"
    os.makedirs(tmp_dir, exist_ok=True)
    
    count = 0
    for item in items:
        vs_name = item['metadata']['name']
        # Sanitização
        for field in ['resourceVersion', 'uid', 'creationTimestamp', 'generation', 'ownerReferences', 'managedFields']:
            if 'metadata' in item: item['metadata'].pop(field, None)
            if 'status' in item: item.pop('status', None)
            
        local_path = f"{tmp_dir}/{vs_name}.json"
        with open(local_path, 'w') as f: json.dump(item, f)
        
        s3.upload_file(local_path, CONFIG['bucket_name'], f"istio-artifacts/{backup_name}/{vs_name}.json")
        count += 1
    
    shutil.rmtree(tmp_dir)
    print_success(f"{count} VirtualServices exportados para S3.")

def restore_istio_from_s3(dst_cluster, backup_name):
    target_str = CONFIG.get('istio_sync_mode', 'all')
    print_step("Restore Istio (VirtualServices)")
    
    validate_cluster_access(GLOBAL_SESSION, dst_cluster)
    
    s3 = GLOBAL_SESSION.client('s3')
    custom_api = client.CustomObjectsApi()
    prefix = f"istio-artifacts/{backup_name}/"
    targets = [t.strip() for t in target_str.split(',')]
    
    try:
        response = s3.list_objects_v2(Bucket=CONFIG['bucket_name'], Prefix=prefix)
        if 'Contents' not in response: 
            print_info("Nenhum artefato Istio encontrado no S3.")
            return

        for obj in response['Contents']:
            filename = obj['Key'].split('/')[-1]
            vs_name = filename.replace('.json', '')
            
            if 'all' not in targets and vs_name not in targets:
                continue

            obj_body = s3.get_object(Bucket=CONFIG['bucket_name'], Key=obj['Key'])['Body'].read().decode('utf-8')
            vs_json = json.loads(obj_body)
            
            try:
                custom_api.create_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_json)
                print(f"   ➕ Criado: {vs_name}")
            except client.exceptions.ApiException as e:
                if e.status == 409: # Conflict/Exists
                    # Pega resourceVersion atual pra update
                    try:
                        exist = custom_api.get_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_name)
                        vs_json['metadata']['resourceVersion'] = exist['metadata']['resourceVersion']
                        custom_api.replace_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_name, vs_json)
                        print(f"   🔄 Atualizado: {vs_name}")
                    except Exception as inner_e:
                        print_error(f"Falha update {vs_name}: {inner_e}")
                else:
                    print_error(f"Falha create {vs_name}: {e}")
    except Exception as e:
        print_error(f"Erro geral restore Istio: {e}")

# --- MAIN EXECUTION ---

def main():
    global GLOBAL_SESSION
    print("\n🚀 --- Migração EKS V64 (Production Safe) ---")

    # 1. Profile & Session
    initial_session, profile_name = select_aws_profile()
    CONFIG['aws_profile'] = profile_name # Salva nome para uso em comandos shell
    
    # 2. Region (Atualiza a sessão global com a região correta)
    GLOBAL_SESSION = select_aws_region(initial_session)
    
    # 3. Bucket & Role (Validação imediata)
    print_step("Configuração de Backup")
    CONFIG['bucket_name'] = get_valid_input("Nome do Bucket Velero", check_bucket, GLOBAL_SESSION)
    CONFIG['role_arn'] = get_valid_input("ARN Role Velero", check_role, GLOBAL_SESSION)
    
    generate_velero_values(CONFIG['bucket_name'], CONFIG['role_arn'], CONFIG['region'])

    # 4. Modo de Operação
    print_step("Modo de Operação")
    print("   [1] FULL_MIGRATION (Backup Src -> Restore Dst)")
    print("   [2] BACKUP_ONLY (Apenas Src)")
    print("   [3] RESTORE_ONLY (Apenas Dst)")
    
    while True:
        m = input("   Escolha: ").strip()
        if m == '1': CONFIG['mode'] = 'FULL_MIGRATION'; break
        if m == '2': CONFIG['mode'] = 'BACKUP_ONLY'; break
        if m == '3': CONFIG['mode'] = 'RESTORE_ONLY'; break
    
    # 5. Definição de Clusters (com Validação K8s imediata)
    src_cluster = None
    dst_cluster = None
    
    if CONFIG['mode'] in ['FULL_MIGRATION', 'BACKUP_ONLY']:
        print_step("Cluster ORIGEM")
        src_cluster = get_valid_input("Nome Cluster Origem", check_cluster_wrapper, GLOBAL_SESSION)
        
    if CONFIG['mode'] in ['FULL_MIGRATION', 'RESTORE_ONLY']:
        print_step("Cluster DESTINO")
        dst_cluster = get_valid_input("Nome Cluster Destino", check_cluster_wrapper, GLOBAL_SESSION)

    # 6. Parâmetros Extras
    restore_backup_name = None
    if CONFIG['mode'] == 'RESTORE_ONLY':
        restore_backup_name = input("   Nome do Backup para Restore (ex: migracao-12345): ").strip()
        if not restore_backup_name:
            print_error("Nome do backup obrigatório para Restore Only."); sys.exit(1)

    CONFIG['istio_sync_mode'] = input("\n   Istio Sync Mode [all]: ").strip() or "all"

    # --- EXECUÇÃO ---
    print("\n" + "="*40)
    print("       INICIANDO PROCESSO")
    print("="*40)

    # Configura Trust Policy
    oidcs = []
    if src_cluster: oidcs.append(get_cluster_oidc(src_cluster))
    if dst_cluster: oidcs.append(get_cluster_oidc(dst_cluster))
    
    trust_mode = 'replace' if CONFIG['mode'] == 'FULL_MIGRATION' else 'append'
    configure_irsa_trust(CONFIG['role_arn'], oidcs, "velero", "velero-server", mode=trust_mode)

    # Backup Flow
    bk_name = restore_backup_name
    if CONFIG['mode'] in ['FULL_MIGRATION', 'BACKUP_ONLY']:
        bk_name = f"migracao-{int(time.time())}"
        
        # Garante contexto
        validate_cluster_access(GLOBAL_SESSION, src_cluster)
        
        install_velero(src_cluster) # (usa o contexto atual do kubeconfig)
        backup_istio_to_s3(src_cluster, bk_name)
        
        print_step(f"Criando Backup: {bk_name}")
        cmd = f"velero backup create {bk_name} --exclude-namespaces {','.join(SYSTEM_NAMESPACES)} --exclude-resources {EXCLUDE_RESOURCES} --wait"
        if run_shell(cmd):
            print_success("Backup concluído com sucesso.")
        else:
            print_error("Falha no Backup."); sys.exit(1)

    # Restore Flow
    if CONFIG['mode'] in ['FULL_MIGRATION', 'RESTORE_ONLY']:
        if not bk_name:
            print_error("Nenhum nome de backup definido."); sys.exit(1)
            
        # Garante contexto destino
        validate_cluster_access(GLOBAL_SESSION, dst_cluster)
        
        install_velero(dst_cluster)
        
        if wait_for_backup_sync(bk_name):
            print_step("Iniciando Restore...")
            cmd = f"velero restore create --from-backup {bk_name} --existing-resource-policy update --exclude-resources {EXCLUDE_RESOURCES} --wait"
            run_shell(cmd)
            restore_istio_from_s3(dst_cluster, bk_name)
            print_success("Processo de Restore Finalizado.")

    print("\n✅ Script Finalizado.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrompido pelo usuário.")
        sys.exit(1)
