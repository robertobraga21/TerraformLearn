import subprocess
import time
import sys
import os
import json
import shutil
import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config as k8s_config

# --- CONFIGURAÇÃO GLOBAL ---
GLOBAL_SESSION = None
CONFIG = {}

# Namespaces que ignoramos no scan de IRSA e no Backup
SYSTEM_NAMESPACES = [
    "default", "kube-system", "kube-public", "kube-node-lease", 
    "velero", "amazon-cloudwatch", "aws-observability", "istio-system", "istio-ingress", "cert-manager", "monitoring",
    "cattle-system", "cattle-fleet-system", "ingress-nginx"
]

EXCLUDE_RESOURCES = "pods,replicasets,endpoints,endpointslices"

# --- 0. UI HELPERS ---
def print_step(msg): print(f"\n🔹 {msg}")
def print_success(msg): print(f"   ✅ {msg}")
def print_error(msg): print(f"   ❌ {msg}")
def print_warning(msg): print(f"   ⚠️  {msg}")
def print_info(msg): print(f"   ℹ️  {msg}")

def run_shell(cmd, ignore_error=False, quiet=True):
    if not quiet: print(f"   [CMD] {cmd}")
    try: 
        # stderr=subprocess.PIPE captura o erro para podermos printar se falhar
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL if quiet else None, stderr=subprocess.PIPE if quiet else None)
        return True
    except subprocess.CalledProcessError as e:
        if not ignore_error: 
            err_msg = e.stderr.decode().strip() if e.stderr else "Erro desconhecido"
            print_error(f"Falha no comando shell: {err_msg}")
        return False

# --- 1. AWS AUTH & VALIDATION ---

def select_aws_profile():
    print_step("Autenticação AWS")
    available_profiles = boto3.Session().available_profiles
    options = ["(Ambiente/Default)"] + sorted(available_profiles)
    
    print("   Perfis encontrados:")
    for idx, prof in enumerate(options):
        print(f"   [{idx}] {prof}")
    
    while True:
        choice = input("\n   Selecione o número do perfil: ").strip()
        if choice.isdigit() and 0 <= int(choice) < len(options):
            selected_profile = None if int(choice) == 0 else options[int(choice)]
            break
        print_error("Opção inválida.")

    print_info(f"Testando credenciais para: {selected_profile if selected_profile else 'ENV_VARS'}...")
    try:
        session = boto3.Session(profile_name=selected_profile)
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        print_success(f"Logado como: {identity['Arn']}")
        return session, selected_profile
    except Exception as e:
        print_error(f"Falha ao autenticar: {e}")
        sys.exit(1)

def select_aws_region(session):
    print_step("Seleção de Região")
    default_region = "us-east-1"
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        valid_regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    except:
        valid_regions = ["us-east-1", "us-east-2", "sa-east-1"]

    while True:
        region = input(f"   Região AWS [{default_region}]: ").strip() or default_region
        if region in valid_regions:
            CONFIG['region'] = region
            print_success(f"Região definida: {region}")
            if CONFIG['aws_profile']:
                return boto3.Session(profile_name=CONFIG['aws_profile'], region_name=region)
            else:
                return boto3.Session(region_name=region)
        print_error(f"Região '{region}' inválida.")

def validate_cluster_access(session, cluster_name):
    print_info(f"Validando acesso ao cluster '{cluster_name}'...")
    eks = session.client('eks')
    try:
        cluster_info = eks.describe_cluster(name=cluster_name)
        arn = cluster_info['cluster']['arn']
        print_success("Cluster encontrado na AWS.")
    except ClientError:
        print_error(f"Cluster '{cluster_name}' não encontrado.")
        return None

    print_info("Atualizando kubeconfig...")
    profile_flag = f"--profile {CONFIG['aws_profile']}" if CONFIG['aws_profile'] else ""
    
    # --- CORREÇÃO DO ERRO 'NO CONTEXT EXISTS' ---
    # Adicionamos --alias {cluster_name} para forçar o nome do contexto a ser igual ao nome do cluster
    cmd = f"aws eks update-kubeconfig --name {cluster_name} --region {CONFIG['region']} --alias {cluster_name} {profile_flag}"
    
    if not run_shell(cmd):
        print_error("Falha ao rodar 'aws eks update-kubeconfig'.")
        return None

    try:
        k8s_config.load_kube_config()
        client.CoreV1Api().list_namespace(limit=1)
        print_success("Conexão API Kubernetes confirmada!")
        return arn
    except Exception as e:
        print_error(f"Falha de conexão K8s: {e}")
        return None

def get_valid_input(prompt, validation_func, session=None):
    while True:
        val = input(f"   {prompt}: ").strip()
        if not val: continue
        if validation_func:
            if validation_func(session, val) if session else validation_func(val): return val
        else: return val

# --- VALIDATORS ---
def check_bucket(session, bucket_name):
    try:
        session.client('s3').head_bucket(Bucket=bucket_name)
        print_success("Bucket válido.")
        return True
    except:
        print_error("Bucket inacessível ou inexistente.")
        return False

def check_role(session, role_arn):
    try:
        session.client('iam').get_role(RoleName=role_arn.split('/')[-1])
        print_success("Role válida.")
        return True
    except:
        print_error("Role inválida.")
        return False

def check_cluster_wrapper(session, cluster_name):
    return validate_cluster_access(session, cluster_name) is not None

# --- 2. VALIDAÇÃO DE APLICAÇÕES (IRSA SCAN) ---
def scan_applications_irsa(cluster_name):
    print_step(f"🕵️  Scan de Aplicações IRSA: {cluster_name}")
    validate_cluster_access(GLOBAL_SESSION, cluster_name)
    
    try:
        v1 = client.CoreV1Api()
        sas = v1.list_service_account_for_all_namespaces().items
    except Exception as e:
        print_error(f"Erro ao listar ServiceAccounts: {e}")
        return

    apps_found = 0
    apps_missing_role = 0
    
    print("\n   --- Relatório de Roles (IRSA) ---")
    for sa in sas:
        ns = sa.metadata.namespace
        name = sa.metadata.name
        if ns in SYSTEM_NAMESPACES: continue
        
        apps_found += 1
        annotations = sa.metadata.annotations or {}
        role_arn = annotations.get('eks.amazonaws.com/role-arn')
        
        if role_arn:
            role_name = role_arn.split('/')[-1]
            print(f"   ✅ [{ns}] {name} -> {role_name}")
        else:
            print(f"   ⚠️  [{ns}] {name} -> SEM ROLE ATRELADA!")
            apps_missing_role += 1

    print("\n" + "-"*30)
    print(f"   Total Apps (User Land): {apps_found}")
    
    if apps_missing_role > 0:
        print_warning(f"Atenção: {apps_missing_role} aplicações não possuem Role IRSA configurada.")
        while True:
            resp = input("   Deseja continuar mesmo assim? (s/n): ").lower()
            if resp == 's': break
            if resp == 'n': sys.exit(1)
    else:
        print_success("Todas as aplicações possuem Roles configuradas.")

# --- 3. VELERO & LOGICA ---

def generate_velero_values(bucket, role_arn, region):
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
    with open("values.yaml", "w") as f: f.write(yaml_content)

def get_cluster_oidc(cluster_name):
    return GLOBAL_SESSION.client('eks').describe_cluster(name=cluster_name)['cluster']['identity']['oidc']['issuer'].replace("https://", "")

def configure_irsa_trust(role_arn, oidcs_list):
    print_step("Configurando Trust Relationships na Role Velero")
    role_name = role_arn.split('/')[-1]
    iam = GLOBAL_SESSION.client('iam')
    sts = GLOBAL_SESSION.client('sts')
    acc = sts.get_caller_identity()["Account"]
    
    try:
        current_policy = iam.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
        new_statements = current_policy.get('Statement', [])
        
        updated = False
        unique_oidcs = list(set(oidcs_list))
        ns, sa = "velero", "velero-server"

        for oidc in unique_oidcs:
            oidc_arn = f"arn:aws:iam::{acc}:oidc-provider/{oidc}"
            exists = False
            for s in new_statements:
                if s.get('Principal', {}).get('Federated') == oidc_arn:
                    cond = s.get('Condition', {}).get('StringEquals', {})
                    if (cond.get(f"{oidc}:sub") == f"system:serviceaccount:{ns}:{sa}" and 
                        cond.get(f"{oidc}:aud") == "sts.amazonaws.com"):
                        exists = True; break
            
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
        
        if updated:
            policy_doc = {"Version": "2012-10-17", "Statement": new_statements}
            iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(policy_doc))
            print_success(f"Trust atualizada para: {role_name}")
        else:
            print_info("Trust Relationship já estava correta.")
    except Exception as e:
        print_error(f"Erro Trust Policy: {e}")

# --- 4. BACKUP/RESTORE ---

def check_bsl_health():
    try:
        res = subprocess.run("kubectl get bsl default -n velero -o json", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.returncode != 0: return False, "BSL Missing"
        data = json.loads(res.stdout)
        phase = data.get('status', {}).get('phase', 'Unknown')
        return (True, "OK") if phase == 'Available' else (False, f"Status: {phase}")
    except: return False, "Erro API K8s"

def wait_for_backup_sync(bk):
    print_info(f"Aguardando sync do backup '{bk}'...")
    for i in range(60): 
        healthy, msg = check_bsl_health()
        if not healthy:
            print_error(f"Velero Unhealthy: {msg}"); return False
        res = subprocess.run(f"velero backup describe {bk}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0: 
            print_success("Backup sincronizado!"); return True
        time.sleep(5)
    return False

def install_velero(context):
    print_step(f"Instalando Velero no contexto: {context}")
    
    # 1. Garante que estamos no contexto certo (Agora com alias funcionando)
    if not run_shell(f"kubectl config use-context {context}", quiet=True):
        print_error(f"Não foi possível mudar para o contexto {context}. Abortando.")
        sys.exit(1)
    
    # 2. Limpeza prévia
    run_shell("helm uninstall velero -n velero", ignore_error=True)
    run_shell("kubectl delete ns velero --timeout=10s --wait=false", ignore_error=True)
    time.sleep(3)
    
    # 3. Criação Robusta do Namespace
    # Substitui o pipe complexo por verificação direta
    check_ns = subprocess.run(f"kubectl get ns velero", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check_ns.returncode != 0:
        print_info("Criando namespace 'velero'...")
        if not run_shell("kubectl create ns velero"):
            print_error("Falha crítica ao criar namespace velero."); sys.exit(1)
    else:
        print_info("Namespace 'velero' já existe.")
    
    # 4. Instalação Helm
    run_shell("helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts", ignore_error=True)
    cmd = "helm upgrade --install velero vmware-tanzu/velero --namespace velero -f values.yaml --reset-values --wait"
    
    if not run_shell(cmd):
        print_error("Falha na instalação Helm. Tentando limpeza forçada e reinstalação...")
        # Força limpeza de finalizers se estiver travado
        run_shell(f"kubectl get namespace velero -o json | tr -d \"\\n\" | sed \"s/\\\"finalizers\\\": \\[[^]]*\\]/\\\"finalizers\\\": []/\" | kubectl replace --raw /api/v1/namespaces/velero/finalize -f -", ignore_error=True)
        run_shell("kubectl create ns velero", ignore_error=True)
        if not run_shell(cmd):
            print_error("Erro fatal: Não foi possível instalar o Velero."); sys.exit(1)
            
    print_success("Velero instalado com sucesso.")

def backup_istio_to_s3(src_cluster, backup_name):
    print_step("Backup Istio (VirtualServices)")
    validate_cluster_access(GLOBAL_SESSION, src_cluster) 
    
    custom_api = client.CustomObjectsApi()
    s3 = GLOBAL_SESSION.client('s3')
    
    try:
        items = custom_api.list_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices").get('items', [])
    except: print_error("Istio não encontrado (pode ignorar se não usa Istio)."); return

    tmp_dir = f"istio_tmp_{backup_name}"; os.makedirs(tmp_dir, exist_ok=True)
    count = 0
    for item in items:
        vs_name = item['metadata']['name']
        for f in ['resourceVersion', 'uid', 'creationTimestamp', 'generation', 'ownerReferences', 'managedFields']:
            if 'metadata' in item: item['metadata'].pop(f, None)
        if 'status' in item: item.pop('status', None)
            
        local_path = f"{tmp_dir}/{vs_name}.json"
        with open(local_path, 'w') as f: json.dump(item, f)
        s3.upload_file(local_path, CONFIG['bucket_name'], f"istio-artifacts/{backup_name}/{vs_name}.json")
        count += 1
    shutil.rmtree(tmp_dir)
    print_success(f"{count} VSs exportados.")

def restore_istio_from_s3(dst_cluster, backup_name):
    print_step("Restore Istio")
    validate_cluster_access(GLOBAL_SESSION, dst_cluster)
    s3 = GLOBAL_SESSION.client('s3'); custom_api = client.CustomObjectsApi()
    prefix = f"istio-artifacts/{backup_name}/"
    
    try:
        objs = s3.list_objects_v2(Bucket=CONFIG['bucket_name'], Prefix=prefix).get('Contents', [])
        if not objs: print_info("Nada no S3 para Istio."); return

        for obj in objs:
            vs_json = json.loads(s3.get_object(Bucket=CONFIG['bucket_name'], Key=obj['Key'])['Body'].read().decode('utf-8'))
            vs_name = vs_json['metadata']['name']
            try:
                custom_api.create_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_json)
                print(f"   ➕ Criado: {vs_name}")
            except client.exceptions.ApiException as e:
                if e.status == 409:
                    exist = custom_api.get_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_name)
                    vs_json['metadata']['resourceVersion'] = exist['metadata']['resourceVersion']
                    custom_api.replace_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_name, vs_json)
                    print(f"   🔄 Atualizado: {vs_name}")
    except Exception as e: print_error(f"Erro restore Istio: {e}")

# --- MAIN ---
def main():
    global GLOBAL_SESSION
    print("\n🚀 --- Migração EKS V66 (Fix Context + IRSA) ---")

    initial_session, profile_name = select_aws_profile()
    CONFIG['aws_profile'] = profile_name
    GLOBAL_SESSION = select_aws_region(initial_session)
    
    CONFIG['bucket_name'] = get_valid_input("Nome do Bucket Velero", check_bucket, GLOBAL_SESSION)
    CONFIG['role_arn'] = get_valid_input("ARN Role Velero", check_role, GLOBAL_SESSION)
    generate_velero_values(CONFIG['bucket_name'], CONFIG['role_arn'], CONFIG['region'])

    print("\nModo: [1] FULL, [2] BACKUP, [3] RESTORE")
    m = input("   Escolha: ").strip()
    mode = 'FULL_MIGRATION' if m == '1' else 'BACKUP_ONLY' if m == '2' else 'RESTORE_ONLY'
    CONFIG['mode'] = mode

    src_cluster, dst_cluster = None, None
    if mode in ['FULL_MIGRATION', 'BACKUP_ONLY']:
        src_cluster = get_valid_input("Cluster Origem", check_cluster_wrapper, GLOBAL_SESSION)
    if mode in ['FULL_MIGRATION', 'RESTORE_ONLY']:
        dst_cluster = get_valid_input("Cluster Destino", check_cluster_wrapper, GLOBAL_SESSION)

    bk_name = None
    if mode == 'RESTORE_ONLY':
        bk_name = input("   Nome Backup: ").strip()

    # --- EXECUÇÃO ---
    oidcs = []
    if src_cluster: oidcs.append(get_cluster_oidc(src_cluster))
    if dst_cluster: oidcs.append(get_cluster_oidc(dst_cluster))
    configure_irsa_trust(CONFIG['role_arn'], oidcs)

    if mode in ['FULL_MIGRATION', 'BACKUP_ONLY']:
        bk_name = f"migracao-{int(time.time())}"
        scan_applications_irsa(src_cluster) # Scan IRSA antes do backup
        
        install_velero(src_cluster)
        backup_istio_to_s3(src_cluster, bk_name)
        
        print_step(f"Backup Velero: {bk_name}")
        cmd = f"velero backup create {bk_name} --exclude-namespaces {','.join(SYSTEM_NAMESPACES)} --exclude-resources {EXCLUDE_RESOURCES} --wait"
        if not run_shell(cmd): sys.exit(1)

    if mode in ['FULL_MIGRATION', 'RESTORE_ONLY']:
        install_velero(dst_cluster)
        if wait_for_backup_sync(bk_name):
            print_step("Iniciando Restore...")
            cmd = f"velero restore create --from-backup {bk_name} --existing-resource-policy update --exclude-resources {EXCLUDE_RESOURCES} --wait"
            run_shell(cmd)
            restore_istio_from_s3(dst_cluster, bk_name)
            
    print("\n✅ Script Finalizado.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(1)
