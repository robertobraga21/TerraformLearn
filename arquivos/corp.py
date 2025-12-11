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

SYSTEM_NAMESPACES = [
    "default", "kube-system", "kube-public", "kube-node-lease", 
    "velero", "amazon-cloudwatch", "aws-observability", "istio-system", "istio-ingress", "cert-manager", "monitoring",
    "cattle-system", "cattle-fleet-system", "ingress-nginx"
]

EXCLUDE_RESOURCES = "pods,replicasets,endpoints,endpointslices"

# --- UI HELPERS ---
def print_step(msg): print(f"\n🔹 {msg}")
def print_success(msg): print(f"   ✅ {msg}")
def print_error(msg): print(f"   ❌ {msg}")
def print_warning(msg): print(f"   ⚠️  {msg}")
def print_info(msg): print(f"   ℹ️  {msg}")

def run_shell(cmd, ignore_error=False, quiet=True):
    if not quiet: print(f"   [CMD] {cmd}")
    try: 
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL if quiet else None, stderr=subprocess.PIPE if quiet else None)
        return True
    except subprocess.CalledProcessError as e:
        if not ignore_error: 
            err_msg = e.stderr.decode().strip() if e.stderr else "Erro desconhecido"
            print_error(f"Falha no comando shell: {err_msg}")
        return False

# --- AWS AUTH ---
def select_aws_profile():
    print_step("Autenticação AWS")
    available_profiles = boto3.Session().available_profiles
    print_info("Digite o nome do perfil AWS (ou Enter para default/env vars):")
    
    while True:
        p_name = input("\n   Nome do Perfil: ").strip()
        if not p_name:
            selected_profile = None; break
        if p_name in available_profiles:
            selected_profile = p_name; break
        else:
            print_error(f"Perfil '{p_name}' não encontrado.")

    display = selected_profile if selected_profile else "ENV_VARS"
    print_info(f"Testando: {display}...")
    try:
        session = boto3.Session(profile_name=selected_profile)
        sts = session.client('sts')
        print_success(f"Logado: {sts.get_caller_identity()['Arn']}")
        return session, selected_profile
    except Exception as e:
        print_error(f"Erro Auth: {e}"); sys.exit(1)

def select_aws_region(session):
    print_step("Região AWS")
    default = "us-east-1"
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        valid = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
    except: valid = ["us-east-1", "us-east-2", "sa-east-1"]

    while True:
        reg = input(f"   Região [{default}]: ").strip() or default
        if reg in valid:
            CONFIG['region'] = reg
            print_success(f"Região: {reg}")
            return boto3.Session(profile_name=CONFIG['aws_profile'], region_name=reg) if CONFIG['aws_profile'] else boto3.Session(region_name=reg)
        print_error("Região inválida.")

def validate_cluster_access(session, cluster_name):
    print_info(f"Acessando cluster '{cluster_name}'...")
    try:
        arn = session.client('eks').describe_cluster(name=cluster_name)['cluster']['arn']
        print_success("Cluster AWS OK.")
    except:
        print_error("Cluster não encontrado na AWS."); return None

    print_info("Atualizando Kubeconfig...")
    prof_flag = f"--profile {CONFIG['aws_profile']}" if CONFIG['aws_profile'] else ""
    # Alias garante nome curto para o contexto
    if not run_shell(f"aws eks update-kubeconfig --name {cluster_name} --region {CONFIG['region']} --alias {cluster_name} {prof_flag}"):
        return None

    try:
        k8s_config.load_kube_config()
        client.CoreV1Api().list_namespace(limit=1)
        print_success("API K8s OK!")
        return arn
    except: print_error("Falha conexão K8s."); return None

def get_valid_input(prompt, val_func, session=None):
    while True:
        val = input(f"   {prompt}: ").strip()
        if not val: continue
        if val_func:
            if val_func(session, val) if session else val_func(val): return val
        else: return val

# --- VALIDATORS ---
def check_bucket(s, b):
    try: s.client('s3').head_bucket(Bucket=b); print_success("Bucket OK."); return True
    except: print_error("Bucket erro."); return False

def check_role(s, r):
    try: s.client('iam').get_role(RoleName=r.split('/')[-1]); print_success("Role OK."); return True
    except: print_error("Role erro."); return False

def check_cluster_wrapper(s, c): return validate_cluster_access(s, c) is not None

# --- IRSA SCAN ---
def scan_applications_irsa(cluster_name):
    print_step(f"Scan IRSA: {cluster_name}")
    validate_cluster_access(GLOBAL_SESSION, cluster_name)
    try: sas = client.CoreV1Api().list_service_account_for_all_namespaces().items
    except: return

    found, missing = 0, 0
    print("\n   --- Apps Analysis ---")
    for sa in sas:
        ns, name = sa.metadata.namespace, sa.metadata.name
        if ns in SYSTEM_NAMESPACES: continue
        
        found += 1
        arn = (sa.metadata.annotations or {}).get('eks.amazonaws.com/role-arn')
        if arn: print(f"   ✅ [{ns}] {name} -> {arn.split('/')[-1]}")
        else:
            print(f"   ⚠️  [{ns}] {name} -> SEM ROLE!")
            missing += 1

    print("-" * 30)
    if missing > 0:
        print_warning(f"{missing} apps sem Role.")
        if input("   Continuar? (s/n): ").lower() != 's': sys.exit(1)
    else: print_success("Todas apps OK.")

# --- VELERO LOGIC ---
def generate_values(bucket, role, region):
    with open("values.yaml", "w") as f:
        f.write(f"""configuration:
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
      eks.amazonaws.com/role-arn: {role}
kubectl:
  image:
    repository: docker.io/bitnamilegacy/kubectl
upgradeCRDs: false
cleanUpCRDs: false
""")

def get_oidc(c):
    return GLOBAL_SESSION.client('eks').describe_cluster(name=c)['cluster']['identity']['oidc']['issuer'].replace("https://", "")

def config_trust(role_arn, oidcs):
    print_step("Trust Relationship (Append)")
    role = role_arn.split('/')[-1]
    iam, sts = GLOBAL_SESSION.client('iam'), GLOBAL_SESSION.client('sts')
    acc = sts.get_caller_identity()["Account"]
    
    try:
        policy = iam.get_role(RoleName=role)['Role']['AssumeRolePolicyDocument']
        stmts = policy.get('Statement', [])
        updated = False
        
        for oidc in list(set(oidcs)):
            arn = f"arn:aws:iam::{acc}:oidc-provider/{oidc}"
            if any(s.get('Principal', {}).get('Federated') == arn for s in stmts): continue
            
            print_info(f"Add OIDC: {oidc}")
            stmts.append({
                "Effect": "Allow", "Principal": {"Federated": arn},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {"StringEquals": {f"{oidc}:sub": "system:serviceaccount:velero:velero-server", f"{oidc}:aud": "sts.amazonaws.com"}}
            })
            updated = True
            
        if updated:
            if len(json.dumps(policy)) > 2000: print_warning("Policy full. Pulando update."); return
            iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": stmts}))
            print_success("Trust atualizada.")
        else: print_success("Trust já configurada.")
    except Exception as e: print_warning(f"Erro Trust: {e}")

# --- INSTALL & BACKUP ---
def install_velero(context):
    print_step(f"Instalando Velero: {context}")
    if not run_shell(f"kubectl config use-context {context}", quiet=True):
        print_error(f"Erro ao mudar contexto para {context}."); sys.exit(1)

    # 1. REMOÇÃO LIMPA E SÍNCRONA
    print_info("Limpando instalação anterior...")
    run_shell("helm uninstall velero -n velero", ignore_error=True)
    
    # Loop de espera para deleção real do namespace
    run_shell("kubectl delete ns velero --timeout=60s", ignore_error=True)
    for i in range(30):
        if subprocess.run("kubectl get ns velero", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            break
        if i == 5: # Se demorar, força limpeza
             run_shell(f"kubectl get namespace velero -o json | tr -d \"\\n\" | sed \"s/\\\"finalizers\\\": \\[[^]]*\\]/\\\"finalizers\\\": []/\" | kubectl replace --raw /api/v1/namespaces/velero/finalize -f -", ignore_error=True)
        time.sleep(2)
        print_info("Aguardando namespace terminar...")

    # 2. INSTALAÇÃO
    print_info("Criando namespace e instalando...")
    if not run_shell("kubectl create ns velero"): print_error("Falha create ns"); sys.exit(1)
    
    run_shell("helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts", ignore_error=True)
    cmd = "helm upgrade --install velero vmware-tanzu/velero --namespace velero -f values.yaml --reset-values --wait --timeout 5m"
    
    if not run_shell(cmd):
        print_error("Helm falhou. Abortando."); sys.exit(1)

    # 3. VERIFICAÇÃO REAL (Running check)
    print_info("Verificando status do Pod...")
    # Espera até o pod estar realmente running
    if not run_shell("kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=velero -n velero --timeout=90s"):
         print_error("Pod do Velero não ficou pronto a tempo."); sys.exit(1)
         
    print_success("Velero rodando e pronto!")

def backup_istio(src, bk_name):
    print_step("Backup Istio (Smart Filter)")
    validate_cluster_access(GLOBAL_SESSION, src)
    
    try: items = client.CustomObjectsApi().list_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices").get('items', [])
    except: print_warning("Istio não encontrado."); return

    tmp = f"istio_tmp_{bk_name}"; os.makedirs(tmp, exist_ok=True)
    cnt, skp = 0, 0
    
    for item in items:
        name = item['metadata']['name'].lower()
        if ("app" in name or "apps" in name) and "admin" not in name:
            for f in ['resourceVersion', 'uid', 'creationTimestamp', 'generation', 'ownerReferences', 'managedFields']:
                if 'metadata' in item: item['metadata'].pop(f, None)
            item.pop('status', None)
            
            path = f"{tmp}/{name}.json"
            with open(path, 'w') as f: json.dump(item, f)
            GLOBAL_SESSION.client('s3').upload_file(path, CONFIG['bucket_name'], f"istio-artifacts/{bk_name}/{name}.json")
            print(f"   📤 Salvo: {name}")
            cnt += 1
        else: skp += 1
            
    shutil.rmtree(tmp)
    print_success(f"Istio: {cnt} salvos, {skp} ignorados.")

def restore_istio(dst, bk_name):
    print_step("Restore Istio")
    validate_cluster_access(GLOBAL_SESSION, dst)
    s3, api = GLOBAL_SESSION.client('s3'), client.CustomObjectsApi()
    
    try:
        objs = s3.list_objects_v2(Bucket=CONFIG['bucket_name'], Prefix=f"istio-artifacts/{bk_name}/").get('Contents', [])
        if not objs: print_info("Sem Istio no backup."); return

        for o in objs:
            data = json.loads(s3.get_object(Bucket=CONFIG['bucket_name'], Key=o['Key'])['Body'].read().decode('utf-8'))
            name = data['metadata']['name']
            try:
                api.create_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", data)
                print(f"   ➕ Criado: {name}")
            except client.exceptions.ApiException as e:
                if e.status == 409:
                    curr = api.get_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", name)
                    data['metadata']['resourceVersion'] = curr['metadata']['resourceVersion']
                    api.replace_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", name, data)
                    print(f"   🔄 Atualizado: {name}")
    except Exception as e: print_error(f"Erro Restore Istio: {e}")

# --- MAIN ---
def main():
    global GLOBAL_SESSION
    print("\n🚀 --- Migração EKS V68 (Robust Install) ---")

    s, p = select_aws_profile()
    CONFIG['aws_profile'] = p
    GLOBAL_SESSION = select_aws_region(s)
    
    CONFIG['bucket_name'] = get_valid_input("Bucket Velero", check_bucket, GLOBAL_SESSION)
    CONFIG['role_arn'] = get_valid_input("Role Velero", check_role, GLOBAL_SESSION)
    generate_values(CONFIG['bucket_name'], CONFIG['role_arn'], CONFIG['region'])

    print("\n[1] FULL  [2] BACKUP  [3] RESTORE")
    m = input("   Opção: ").strip()
    mode = 'FULL_MIGRATION' if m == '1' else 'BACKUP_ONLY' if m == '2' else 'RESTORE_ONLY'

    src, dst = None, None
    if mode in ['FULL_MIGRATION', 'BACKUP_ONLY']: src = get_valid_input("Cluster Origem", check_cluster_wrapper, GLOBAL_SESSION)
    if mode in ['FULL_MIGRATION', 'RESTORE_ONLY']: dst = get_valid_input("Cluster Destino", check_cluster_wrapper, GLOBAL_SESSION)
    
    bk = input("   Nome Backup: ").strip() if mode == 'RESTORE_ONLY' else f"migracao-{int(time.time())}"

    # Execution
    oidcs = []
    if src: oidcs.append(get_oidc(src))
    if dst: oidcs.append(get_oidc(dst))
    config_trust(CONFIG['role_arn'], oidcs)

    if mode in ['FULL_MIGRATION', 'BACKUP_ONLY']:
        scan_applications_irsa(src)
        install_velero(src)
        backup_istio(src, bk)
        
        print_step(f"Criando Backup: {bk}")
        # Garante contexto antes do backup command
        run_shell(f"kubectl config use-context {src}", quiet=True)
        if not run_shell(f"velero backup create {bk} --exclude-namespaces {','.join(SYSTEM_NAMESPACES)} --exclude-resources {EXCLUDE_RESOURCES} --wait"):
            sys.exit(1)

    if mode in ['FULL_MIGRATION', 'RESTORE_ONLY']:
        install_velero(dst)
        print_step(f"Aguardando Sync Backup: {bk}")
        # Loop de verificação BSL
        for i in range(60):
             if run_shell(f"velero backup describe {bk}", quiet=True): break
             time.sleep(5)
             if i == 59: print_error("Backup não sincronizou."); sys.exit(1)
             
        print_step("Restaurando...")
        run_shell(f"velero restore create --from-backup {bk} --existing-resource-policy update --exclude-resources {EXCLUDE_RESOURCES} --wait")
        restore_istio(dst, bk)

    print("\n✅ Finalizado com sucesso.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: sys.exit(0)
