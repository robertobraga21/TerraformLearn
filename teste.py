import subprocess
import time
import sys
import json
import boto3
import re
from botocore.exceptions import ClientError
from kubernetes import client, config as k8s_config

# --- CONFIGURAÇÃO GLOBAL ---
CONFIG = {}

SYSTEM_NAMESPACES = [
    "default", "kube-system", "kube-public", "kube-node-lease", 
    "velero", "amazon-cloudwatch", "aws-observability", "istio-system", "istio-ingress", "cert-manager", "monitoring"
]

EXCLUDE_RESOURCES = "pods,replicasets,endpoints,endpointslices"

# --- 0. HELPERS ---
def get_smart_input(prompt_text, default=None, options=None, regex=None):
    while True:
        value = input(prompt_text).strip()
        if not value:
            if default is not None: return default
            print("   ❌ Este campo é obrigatório.")
            continue
        if options:
            if value.lower() not in [str(o).lower() for o in options]:
                if len(options) > 10: print(f"   ❌ Opção inválida.")
                else: print(f"   ❌ Opção inválida. Escolha entre: {options}")
                continue
            return value
        if regex and not re.match(regex, value):
            print(f"   ❌ Formato inválido.")
            continue
        return value

def run_shell(cmd, ignore_error=False, quiet=False):
    try: 
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL if quiet else None)
        return True
    except: 
        if not ignore_error: print(f"❌ Erro comando: {cmd}"); sys.exit(1)
        return False

# --- 1. SETUP INICIAL (PROFILE ENFORCED) ---
def get_inputs_initial():
    print("\n🚀 --- Migração Cluster EKS  ---")
    
    CONFIG['env'] = get_smart_input("   Ambiente (DEV, HML, PRD): ", options=['DEV', 'HML', 'PRD']).upper()
    
    print("\n🔑 --- Autenticação AWS (Profile Obrigatório) ---")
    
    available_profiles = boto3.Session().available_profiles
    if not available_profiles:
        print("   ⛔ ERRO: Nenhum profile AWS encontrado em ~/.aws/credentials ou ~/.aws/config.")
        sys.exit(1)
        
    print(f"   Profiles detectados: {', '.join(available_profiles)}")
    
    while True:
        p_input = get_smart_input("   Digite o nome do Profile: ")
        if p_input in available_profiles:
            CONFIG['aws_profile'] = p_input
            break
        print(f"   ❌ O profile '{p_input}' não existe. Tente novamente.")

    try:
        temp_session = boto3.Session(profile_name=CONFIG['aws_profile'])
        detected_region = temp_session.region_name if temp_session.region_name else "us-east-1"
    except:
        detected_region = "us-east-1"

    try: valid_regions = boto3.Session().get_available_regions('eks')
    except: valid_regions = ['us-east-1', 'us-east-2', 'sa-east-1']

    CONFIG['region'] = get_smart_input(
        f"   Região AWS [{detected_region}]: ", 
        default=detected_region, 
        options=valid_regions
    )
    
    CONFIG['cleanup'] = False
    if get_smart_input("\n🧹 Limpar instalação anterior (Reset)? (s/n) [n]: ", default='n', options=['s', 'n']).lower() == 's':
        CONFIG['cleanup'] = True

def get_aws_session():
    return boto3.Session(profile_name=CONFIG['aws_profile'], region_name=CONFIG['region'])

# --- 2. SELEÇÃO DE CLUSTER ---
def select_cluster(prompt_msg):
    eks = get_aws_session().client('eks')
    print(f"   🔍 Listando clusters na região {CONFIG['region']}...")
    try:
        clusters = eks.list_clusters()['clusters']
    except Exception as e:
        print(f"      ⛔ Erro ao listar clusters: {e}"); sys.exit(1)

    if not clusters:
        print("      ❌ Nenhum cluster encontrado nesta região.")
        sys.exit(1)

    print(prompt_msg)
    for idx, name in enumerate(clusters):
        print(f"      [{idx}] {name}")
    
    while True:
        sel = get_smart_input("      Selecione o número: ")
        if sel.isdigit() and 0 <= int(sel) < len(clusters):
            cluster_name = clusters[int(sel)]
            try:
                arn = eks.describe_cluster(name=cluster_name)['cluster']['arn']
                print(f"      ✅ Selecionado: {cluster_name}")
                context = resolve_kube_context_logic(cluster_name, arn)
                return cluster_name, context
            except Exception as e:
                print(f"      ❌ Erro ao validar cluster escolhido: {e}")
                sys.exit(1)
        print(f"      ❌ Inválido. Digite um número entre 0 e {len(clusters)-1}.")

def resolve_kube_context_logic(cluster_name, cluster_arn):
    try:
        ctxs, _ = k8s_config.list_kube_config_contexts()
        if ctxs:
            for c in ctxs:
                if c['name'] == cluster_arn or c['name'] == cluster_name:
                    return c['name']
    except: pass
    
    print(f"      ℹ️  Gerando contexto local para {cluster_name}...")
    cmd = f"aws eks update-kubeconfig --name {cluster_name} --region {CONFIG['region']} --profile {CONFIG['aws_profile']}"
    run_shell(cmd, quiet=True)
    return cluster_arn

# --- 3. PREPARAÇÃO (MANUAL INPUT) ---
def ensure_role_permissions(role_name):
    # Skip validation logic for Production
    print(f"   🛡️  [SKIP] Validação de permissões ignorada (Ambiente Controlado).")
    print(f"       ℹ️  Assumindo que a role '{role_name}' já possui acesso ao S3 e EC2.")

def generate_velero_values(bucket, role_arn, region):
    print(f"\n📝 Gerando 'values.yaml'...")
    yaml_content = f"""configuration:
  backupStorageLocation:
    - bucket: {bucket}
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
    except Exception as e: print(f"❌ Erro values.yaml: {e}"); sys.exit(1)

def get_cluster_oidc(name):
    return get_aws_session().client('eks').describe_cluster(name=name)['cluster']['identity']['oidc']['issuer'].replace("https://", "")

def get_role_arn(name):
    return get_aws_session().client('iam').get_role(RoleName=name)['Role']['Arn']

def update_trust_policy(role, oidc, ns, sa):
    iam = get_aws_session().client('iam'); sts = get_aws_session().client('sts')
    acc = sts.get_caller_identity()["Account"]
    oidc_arn = f"arn:aws:iam::{acc}:oidc-provider/{oidc}"
    try:
        pol = iam.get_role(RoleName=role)['Role']['AssumeRolePolicyDocument']
        for s in pol['Statement']:
            if s.get('Principal', {}).get('Federated') == oidc_arn:
                cond = s.get('Condition', {}).get('StringEquals', {})
                for k,v in cond.items():
                    if f"{oidc}:sub" in k and v == f"system:serviceaccount:{ns}:{sa}": return False
        print(f"   ➕ Autorizando OIDC na Role {role} para {sa}...")
        pol['Statement'].append({
            "Effect": "Allow", "Principal": {"Federated": oidc_arn}, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {f"{oidc}:sub": f"system:serviceaccount:{ns}:{sa}"}}
        })
        iam.update_assume_role_policy(RoleName=role, PolicyDocument=json.dumps(pol))
        return True
    except Exception as e: print(f"⚠️ Erro trust: {e}"); return False

def run_pre_flight_irsa(ctx, dest_oidc):
    print(f"\n🕵️  [IRSA] Preparando Apps em {ctx}...")
    k8s_config.load_kube_config(context=ctx); v1 = client.CoreV1Api(); cnt = 0
    for sa in v1.list_service_account_for_all_namespaces().items:
        ns = sa.metadata.namespace
        if ns in SYSTEM_NAMESPACES: continue
        arn = (sa.metadata.annotations or {}).get('eks.amazonaws.com/role-arn')
        if arn:
            r = arn.split("/")[-1]
            if r == CONFIG['velero_role'] or "aws-service-role" in r: continue
            if update_trust_policy(r, dest_oidc, ns, sa.metadata.name): cnt += 1; time.sleep(0.2)
    print(f"✅ {cnt} apps preparadas.")

# --- 4. ISTIO SYNC ---
def sanitize_k8s_object(obj):
    if 'metadata' in obj:
        for field in ['resourceVersion', 'uid', 'creationTimestamp', 'generation', 'ownerReferences', 'managedFields']:
            obj['metadata'].pop(field, None)
        annotations = obj['metadata'].get('annotations', {})
        annotations.pop('kubectl.kubernetes.io/last-applied-configuration', None)
        obj['metadata']['annotations'] = annotations
    obj.pop('status', None)
    return obj

def sync_istio_resources(src_ctx, dst_ctx):
    print(f"\n🕸️  [ISTIO] Sincronizando VirtualServices...")
    k8s_config.load_kube_config(context=src_ctx)
    custom_api_src = client.CustomObjectsApi()
    ns_ignore_istio = [ns for ns in SYSTEM_NAMESPACES if ns != "istio-system"]
    group = "networking.istio.io"; version = "v1beta1"; plural = "virtualservices"
    candidates = []
    try:
        resp = custom_api_src.list_cluster_custom_object(group, version, plural)
        valid_items = [i for i in resp.get('items', []) if i['metadata']['namespace'] not in ns_ignore_istio]
        if not valid_items: print("    ℹ️  Nenhum VS encontrado."); return
        print("\n📝 --- Selecione os VirtualServices ---")
        for idx, item in enumerate(valid_items):
            print(f"   [{idx}] {item['metadata']['namespace']} / {item['metadata']['name']}")
        
        while True:
            sel = get_smart_input("\n👉 Números (ex: 0,2), 'all' ou 'none': ", default='none').lower()
            if sel == 'none': return
            if sel == 'all':
                indices = range(len(valid_items))
                break
            try:
                parts = [int(x.strip()) for x in sel.split(',') if x.strip().isdigit()]
                if not parts or any(p < 0 or p >= len(valid_items) for p in parts):
                    print(f"   ❌ Índices fora do intervalo.")
                    continue
                indices = parts
                break
            except: print("   ❌ Formato inválido.")

        candidates = [sanitize_k8s_object(valid_items[i]) for i in indices]
    except Exception as e: print(f"    ⚠️  Erro listagem: {e}"); return

    if not candidates: return
    print(f"    📤 Replicando {len(candidates)} VSs no Destino...")
    k8s_config.load_kube_config(context=dst_ctx)
    custom_api_dst = client.CustomObjectsApi()
    cnt = 0
    for body in candidates:
        ns = body['metadata']['namespace']; name = body['metadata']['name']
        try: client.CoreV1Api().create_namespace(client.V1Namespace(metadata=client.V1ObjectMeta(name=ns)))
        except: pass
        try:
            custom_api_dst.create_namespaced_custom_object(group, version, ns, plural, body)
            print(f"    ✅ Criado: {ns}/{name}"); cnt += 1
        except client.exceptions.ApiException as e:
            if e.status == 409:
                try:
                    exist = custom_api_dst.get_namespaced_custom_object(group, version, ns, plural, name)
                    body['metadata']['resourceVersion'] = exist['metadata']['resourceVersion']
                    custom_api_dst.replace_namespaced_custom_object(group, version, ns, plural, name, body)
                    print(f"    🔄 Atualizado: {ns}/{name}"); cnt += 1
                except: print(f"    ❌ Falha update: {name}")
            else: print(f"    ❌ Falha create: {name}")
    print(f"✅ {cnt} VSs sincronizados.")

# --- 5. VELERO CONTROL ---
def wait_for_backup_sync(bk):
    print(f"⏳ Aguardando sync do backup '{bk}' no destino...")
    for i in range(24):
        res = subprocess.run(f"velero backup describe {bk}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0: print(f"   ✅ Backup disponível!"); return True
        time.sleep(5)
    print("\n❌ Timeout sync."); return False

def force_delete_namespace(ns):
    cmd = (f"kubectl get namespace {ns} -o json | tr -d \"\\n\" | sed \"s/\\\"finalizers\\\": \\[[^]]*\\]/\\\"finalizers\\\": []/\" | kubectl replace --raw /api/v1/namespaces/{ns}/finalize -f -")
    run_shell(cmd, ignore_error=True, quiet=True)

def cleanup_velero(context):
    print(f"🧹 [CLEANUP] Limpando {context}...")
    run_shell(f"kubectl config use-context {context}", quiet=True)
    run_shell("helm uninstall velero -n velero", ignore_error=True, quiet=True)
    proc = subprocess.Popen("kubectl delete ns velero --timeout=15s", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try: proc.wait(timeout=15)
    except subprocess.TimeoutExpired: force_delete_namespace("velero")
    time.sleep(5)

def install_velero(context):
    if CONFIG['cleanup']: cleanup_velero(context)
    print(f"⚓ [{context}] Instalando Velero...")
    run_shell(f"kubectl config use-context {context}", quiet=True)
    run_shell("kubectl create ns velero --dry-run=client -o yaml | kubectl apply -f -", quiet=True)
    cmd = f"helm upgrade --install velero vmware-tanzu/velero --namespace velero -f values.yaml --reset-values --wait"
    run_shell(cmd, quiet=True)
    run_shell("kubectl rollout restart deployment velero -n velero", quiet=True)

# --- MAIN ---
def main():
    get_inputs_initial()
    s3 = get_aws_session().client('s3')
    iam = get_aws_session().client('iam')

    print("\n🖥️ --- Definição dos Clusters ---")
    c_src, ctx_src = select_cluster("   \n👉 Selecione o Cluster ORIGEM:")
    c_dst, ctx_dst = select_cluster("   \n👉 Selecione o Cluster DESTINO:")

    # --- NOVO BLOCO: INPUT MANUAL ---
    print("\n📦 --- Definição de Recursos (Manual) ---")
    
    # Bucket Input e Validação
    while True:
        b_input = get_smart_input("   Digite o nome do Bucket S3 de Backup: ")
        try:
            # Verifica se o bucket existe e é acessível
            s3.head_bucket(Bucket=b_input)
            print(f"      ✅ Bucket '{b_input}' verificado.")
            CONFIG['bucket'] = b_input
            break
        except Exception as e:
            print(f"      ❌ Erro ao validar bucket: {e}")
            if get_smart_input("      Deseja tentar outro nome? (s/n) [s]: ", default='s').lower() == 'n':
                sys.exit(1)

    # Role Input e Validação
    while True:
        r_input = get_smart_input("   Digite o nome da IAM Role do Velero: ")
        try:
            # Verifica se a role existe
            iam.get_role(RoleName=r_input)
            print(f"      ✅ Role '{r_input}' verificada.")
            CONFIG['velero_role'] = r_input
            break
        except Exception as e:
            print(f"      ❌ Erro ao validar role: {e}")
            if get_smart_input("      Deseja tentar outro nome? (s/n) [s]: ", default='s').lower() == 'n':
                sys.exit(1)
    # --------------------------------

    ensure_role_permissions(CONFIG['velero_role'])
    generate_velero_values(CONFIG['bucket'], get_role_arn(CONFIG['velero_role']), CONFIG['region'])

    print("\n☁️  Configurando OIDCs e Permissões...")
    oidc_src = get_cluster_oidc(c_src); oidc_dst = get_cluster_oidc(c_dst)
    update_trust_policy(CONFIG['velero_role'], oidc_src, "velero", "velero-server")
    update_trust_policy(CONFIG['velero_role'], oidc_dst, "velero", "velero-server")
    
    run_pre_flight_irsa(ctx_src, oidc_dst)
    sync_istio_resources(ctx_src, ctx_dst)

    bk = f"migracao-{CONFIG['env'].lower()}-{int(time.time())}"

    print(f"\n--- 🚀 FASE ORIGEM ---")
    install_velero(ctx_src)
    print(f"💾 Criando Backup: {bk}")
    try:
        run_shell(f"velero backup create {bk} --exclude-namespaces {','.join(SYSTEM_NAMESPACES)} --exclude-resources {EXCLUDE_RESOURCES} --wait")
        print("⏳ Aguardando 60s para consolidação do Snapshot na AWS...")
        time.sleep(60) 
    except SystemExit:
        if get_smart_input("   ⚠️ Backup falhou. Continuar? (s/n): ", default='n', options=['s','n']).lower() != 's': sys.exit(1)

    print(f"\n--- 🛬 FASE DESTINO ---")
    install_velero(ctx_dst)
    
    if wait_for_backup_sync(bk):
        print("\n✋ --- Ponto de Decisão ---")
        if get_smart_input(f"   Restaurar backup '{bk}' AGORA? (s/n) [n]: ", default='n', options=['s','n']).lower() == 's':
            print(f"♻️  Iniciando Restore...")
            run_shell(f"velero restore create --from-backup {bk} --existing-resource-policy update --exclude-resources {EXCLUDE_RESOURCES} --wait")
            print("\n🎉 Migração realizada com sucesso!")
        else:
            print(f"\nℹ️  Restore adiado. Comando para rodar depois:")
            print(f"   velero restore create --from-backup {bk} --existing-resource-policy update --exclude-resources {EXCLUDE_RESOURCES} --wait")
    else:
        print("\n⛔ Restore abortado (Timeout).")

    print("\n✅ Fim do Script.")

if __name__ == "__main__":
    main()
