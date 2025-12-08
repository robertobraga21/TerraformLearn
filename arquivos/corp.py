import subprocess
import time
import sys
import os
import json
import boto3
from botocore.exceptions import ClientError
from kubernetes import client, config as k8s_config

# --- CONFIGURAÇÃO GLOBAL ---
CONFIG = {}

SYSTEM_NAMESPACES = [
    "default", "kube-system", "kube-public", "kube-node-lease", 
    "velero", "amazon-cloudwatch", "aws-observability", "istio-system", "istio-ingress", "cert-manager", "monitoring",
    "cattle-system", "cattle-fleet-system"
]

EXCLUDE_RESOURCES = "pods,replicasets,endpoints,endpointslices"

VELERO_IAM_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:CreateTags",
                "ec2:CreateVolume", "ec2:CreateSnapshot", "ec2:DeleteSnapshot"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject", "s3:DeleteObject", "s3:PutObject",
                "s3:AbortMultipartUpload", "s3:ListBucket"
            ],
            "Resource": "*" 
        }
    ]
}

# --- 0. HELPERS ---
def get_env_opt(var_name, default=None):
    return os.getenv(var_name, default)

def get_required_env(var_name):
    val = os.getenv(var_name)
    if not val or val.strip() == "":
        print(f"⛔ ERRO CRÍTICO: Variável obrigatória '{var_name}' não definida.")
        sys.exit(1)
    return val.strip()

def run_shell(cmd, ignore_error=False, quiet=False):
    if not quiet: print(f"   [CMD] {cmd}")
    try: 
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL if quiet else None)
        return True
    except: 
        if not ignore_error: 
            print(f"❌ Falha na execução do comando.")
            sys.exit(1)
        return False

# --- 1. SETUP ---
def load_config():
    print("\n🚀 --- Migração EKS V61 (Host Native) ---")
    
    CONFIG['region'] = get_required_env("AWS_REGION")
    CONFIG['mode'] = get_required_env("OPERATION_MODE") 
    
    # Perfil injetado pelo Jenkins Choice Parameter
    CONFIG['aws_profile'] = get_required_env("AWS_PROFILE")
    
    CONFIG['bucket_name'] = get_required_env("VELERO_BUCKET_NAME")
    CONFIG['role_arn'] = get_required_env("VELERO_ROLE_ARN")
    
    CONFIG['cluster_src'] = None
    CONFIG['cluster_dst'] = None
    
    if CONFIG['mode'] in ['FULL_MIGRATION', 'BACKUP_ONLY']:
        CONFIG['cluster_src'] = get_required_env("CLUSTER_SOURCE_NAME")
        
    if CONFIG['mode'] in ['FULL_MIGRATION', 'RESTORE_ONLY']:
        CONFIG['cluster_dst'] = get_required_env("CLUSTER_DEST_NAME")

    CONFIG['restore_backup_name'] = get_env_opt("BACKUP_NAME_TO_RESTORE")
    if CONFIG['mode'] == 'RESTORE_ONLY' and not CONFIG['restore_backup_name']:
        print("⛔ ERRO: Para RESTORE_ONLY, forneça 'BACKUP_NAME_TO_RESTORE'.")
        sys.exit(1)

    CONFIG['istio_sync_mode'] = get_env_opt("ISTIO_SYNC_MODE", "all").lower()
    CONFIG['cleanup'] = get_env_opt("CLEANUP_ENABLED", "false").lower() == 'true'

    print(f"   ℹ️  Modo: {CONFIG['mode']}")
    print(f"   ℹ️  Profile: {CONFIG['aws_profile']}")
    print(f"   ℹ️  Região: {CONFIG['region']}")
    if CONFIG['cluster_src']: print(f"   ℹ️  Origem: {CONFIG['cluster_src']}")
    if CONFIG['cluster_dst']: print(f"   ℹ️  Destino: {CONFIG['cluster_dst']}")

def get_aws_session():
    # Usa o profile selecionado
    return boto3.Session(profile_name=CONFIG['aws_profile'], region_name=CONFIG['region'])

# --- 2. VALIDAÇÃO AWS ---
def validate_bucket(bucket_name):
    print(f"\n📦 Validando Bucket S3: {bucket_name}")
    try:
        get_aws_session().client('s3').head_bucket(Bucket=bucket_name)
        print(f"   ✅ Bucket acessível.")
    except ClientError as e:
        print(f"   ⛔ ERRO Bucket: {e}"); sys.exit(1)

def extract_and_validate_role(role_arn):
    print(f"\n👤 Validando Role IAM: {role_arn}")
    try:
        role_name = role_arn.split('/')[-1]
        get_aws_session().client('iam').get_role(RoleName=role_name)
        print(f"   ✅ Role válida.")
        return role_name
    except Exception as e:
        print(f"   ⛔ ERRO Role: {e}"); sys.exit(1)

# --- 3. CONTEXTO K8S ---
def setup_kube_context(cluster_name):
    print(f"   🔍 Configurando kubeconfig para '{cluster_name}'...")
    try:
        # Usa --profile no comando AWS CLI
        cmd = f"aws eks update-kubeconfig --name {cluster_name} --region {CONFIG['region']} --profile {CONFIG['aws_profile']}"
        run_shell(cmd, quiet=True)
        eks = get_aws_session().client('eks')
        return eks.describe_cluster(name=cluster_name)['cluster']['arn']
    except Exception as e:
        print(f"      ⛔ Erro config cluster: {e}"); sys.exit(1)

# --- 4. PREPARAÇÃO ---
def generate_velero_values(bucket, role_arn, region):
    print(f"\n📝 Gerando 'values.yaml'...")
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
    except Exception as e: print(f"❌ Erro values.yaml: {e}"); sys.exit(1)

def get_cluster_oidc(name):
    return get_aws_session().client('eks').describe_cluster(name=name)['cluster']['identity']['oidc']['issuer'].replace("https://", "")

def ensure_role_permissions(role_name, bucket_name):
    print(f"   🛡️  Blindando permissões na role '{role_name}'...")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeVolumes", "ec2:DescribeSnapshots", "ec2:CreateTags",
                    "ec2:CreateVolume", "ec2:CreateSnapshot", "ec2:DeleteSnapshot"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject", "s3:DeleteObject", "s3:PutObject",
                    "s3:AbortMultipartUpload", "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ]
            }
        ]
    }
    try:
        get_aws_session().client('iam').put_role_policy(RoleName=role_name, PolicyName="VeleroPerms", PolicyDocument=json.dumps(policy_doc))
        print(f"      ✅ Policy aplicada.")
    except Exception as e: print(f"      ⚠️  Falha permissoes: {e}")

# --- 5. LÓGICA CORE (TRUST / IRSA) ---
def configure_irsa_trust(role_name, oidcs_list, ns, sa, mode='append'):
    iam = get_aws_session().client('iam'); sts = get_aws_session().client('sts')
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
            for s in new_statements:
                if s.get('Principal', {}).get('Federated') == oidc_arn:
                    cond = s.get('Condition', {}).get('StringEquals', {})
                    for k, v in cond.items():
                        if f"{oidc}:sub" in k and v == f"system:serviceaccount:{ns}:{sa}":
                            exists = True
                            break
            if not exists:
                new_statements.append({
                    "Effect": "Allow",
                    "Principal": {"Federated": oidc_arn},
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {"StringEquals": {f"{oidc}:sub": f"system:serviceaccount:{ns}:{sa}"}}
                })
                updated = True
        
        if updated or mode == 'replace':
            policy_doc = {"Version": "2012-10-17", "Statement": new_statements}
            iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=json.dumps(policy_doc))
            return True
        return False
    except Exception as e:
        print(f"      ⛔ Erro Trust Policy ({mode}): {e}")
        return False

def run_pre_flight_irsa(ctx, oidcs_list, mode):
    print(f"\n🕵️  [IRSA] Scan em {ctx}...")
    try:
        k8s_config.load_kube_config(config_file=os.environ["KUBECONFIG"], context=ctx)
        v1 = client.CoreV1Api(); items = v1.list_service_account_for_all_namespaces().items
    except: print("   ⚠️  Erro lendo SAs."); return

    cnt = 0
    for sa in items:
        ns = sa.metadata.namespace
        if ns in SYSTEM_NAMESPACES: continue
        arn = (sa.metadata.annotations or {}).get('eks.amazonaws.com/role-arn')
        if arn:
            r_name = arn.split("/")[-1]
            if r_name == CONFIG['role_name'] or "aws-service-role" in r_name: continue
            if configure_irsa_trust(r_name, oidcs_list, ns, sa.metadata.name, mode=mode): 
                cnt += 1; time.sleep(0.2)
    print(f"✅ {cnt} apps processadas.")

# --- 6. ISTIO SYNC ---
def sanitize_k8s_object(obj):
    if 'metadata' in obj:
        for field in ['resourceVersion', 'uid', 'creationTimestamp', 'generation', 'ownerReferences', 'managedFields']:
            obj['metadata'].pop(field, None)
        annotations = obj['metadata'].get('annotations', {})
        annotations.pop('kubectl.kubernetes.io/last-applied-configuration', None)
        obj['metadata']['annotations'] = annotations
    obj.pop('status', None)
    return obj

def backup_istio_to_s3(src_ctx, backup_name):
    print(f"\n🕸️  [ISTIO] Exportando S3...")
    k8s_config.load_kube_config(config_file=os.environ["KUBECONFIG"], context=src_ctx)
    custom_api = client.CustomObjectsApi(); s3 = get_aws_session().client('s3')
    
    try:
        resp = custom_api.list_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices")
        items = resp.get('items', [])
    except Exception as e: print(f"   ⚠️  Erro Istio: {e}"); return

    tmp_dir = f"istio_tmp_{backup_name}"
    os.makedirs(tmp_dir, exist_ok=True)
    count = 0
    for item in items:
        vs_name = item['metadata']['name']
        local_path = f"{tmp_dir}/{vs_name}.json"
        with open(local_path, 'w') as f: json.dump(sanitize_k8s_object(item), f)
        s3.upload_file(local_path, CONFIG['bucket_name'], f"istio-artifacts/{backup_name}/{vs_name}.json")
        print(f"   📤 Exportado: {vs_name}")
        count += 1
    shutil.rmtree(tmp_dir)
    print(f"   ✅ {count} VSs salvos.")

def restore_istio_from_s3(dst_ctx, backup_name):
    target_str = CONFIG['istio_sync_mode']
    if not target_str: return
    print(f"\n🕸️  [ISTIO] Restaurando do S3...")
    s3 = get_aws_session().client('s3')
    k8s_config.load_kube_config(config_file=os.environ["KUBECONFIG"], context=dst_ctx)
    custom_api = client.CustomObjectsApi()
    prefix = f"istio-artifacts/{backup_name}/"
    targets = [t.strip() for t in target_str.split(',')]
    
    try:
        response = s3.list_objects_v2(Bucket=CONFIG['bucket_name'], Prefix=prefix)
        if 'Contents' not in response: print("   ⚠️  Nada no S3."); return

        for obj in response['Contents']:
            filename = obj['Key'].split('/')[-1]
            vs_name = filename.replace('.json', '')
            if vs_name not in targets and 'all' not in targets: continue

            obj_body = s3.get_object(Bucket=CONFIG['bucket_name'], Key=obj['Key'])['Body'].read().decode('utf-8')
            vs_json = json.loads(obj_body)
            try:
                custom_api.create_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_json)
                print(f"   ✅ Restaurado: {vs_name}")
            except client.exceptions.ApiException as e:
                if e.status == 409:
                    try:
                        exist = custom_api.get_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_name)
                        vs_json['metadata']['resourceVersion'] = exist['metadata']['resourceVersion']
                        custom_api.replace_namespaced_custom_object("networking.istio.io", "v1beta1", "istio-system", "virtualservices", vs_name, vs_json)
                        print(f"   🔄 Atualizado: {vs_name}")
                    except: print(f"   ❌ Falha update: {vs_name}")
                else: print(f"   ❌ Falha create: {vs_name}")
    except Exception as e: print(f"   ❌ Erro Istio Restore: {e}")

# --- 7. VELERO CONTROL ---
def check_bsl_health():
    try:
        res = subprocess.run("kubectl get bsl default -n velero -o json", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if res.returncode != 0: return False, "BSL Missing"
        data = json.loads(res.stdout)
        phase = data.get('status', {}).get('phase', 'Unknown')
        if phase == 'Available': return True, "OK"
        return False, f"Status: {phase}"
    except: return False, "Erro API"

def wait_for_backup_sync(bk):
    print(f"⏳ Aguardando sync do backup '{bk}' no destino...")
    for i in range(60): 
        healthy, msg = check_bsl_health()
        if not healthy:
            print(f"\n⛔ VELERO UNHEALTHY: {msg}. Abortando."); return False
        
        res = subprocess.run(f"velero backup describe {bk}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0: print(f"   ✅ Backup sincronizado!"); return True
        
        if i % 6 == 0: sys.stdout.write("."); sys.stdout.flush()
        time.sleep(5)
    print("\n❌ Timeout sync."); return False

def cleanup_velero(context):
    print(f"🧹 [CLEANUP] Limpando {context}...")
    run_shell(f"kubectl config use-context {context}", quiet=True)
    run_shell("helm uninstall velero -n velero", ignore_error=True, quiet=True)
    run_shell("kubectl delete ns velero --timeout=5s --wait=false", ignore_error=True, quiet=True)
    for i in range(20):
        if subprocess.run("kubectl get ns velero", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0: return
        if i == 6: run_shell(f"kubectl get namespace velero -o json | tr -d \"\\n\" | sed \"s/\\\"finalizers\\\": \\[[^]]*\\]/\\\"finalizers\\\": []/\" | kubectl replace --raw /api/v1/namespaces/velero/finalize -f -", ignore_error=True, quiet=True)
        time.sleep(2)

def install_velero(context):
    cleanup_velero(context)
    print(f"⚓ [{context}] Instalando Velero...")
    run_shell(f"kubectl config use-context {context}", quiet=True)
    run_shell("kubectl create ns velero --dry-run=client -o yaml | kubectl apply -f -", quiet=True)
    run_shell("helm repo add vmware-tanzu https://vmware-tanzu.github.io/helm-charts", quiet=True)
    run_shell("helm repo update", quiet=True)
    cmd = f"helm upgrade --install velero vmware-tanzu/velero --namespace velero -f values.yaml --reset-values --wait"
    if not run_shell(cmd, quiet=True, ignore_error=True):
        cleanup_velero(context); run_shell("kubectl create ns velero --dry-run=client -o yaml | kubectl apply -f -", quiet=True); run_shell(cmd, quiet=True)
    run_shell("kubectl rollout restart deployment velero -n velero", quiet=True)

# --- MAIN FLOWS ---
def execute_backup_flow(ctx_src, allowed_oidcs, trust_mode):
    bk = f"migracao-{int(time.time())}"
    configure_irsa_trust(CONFIG['role_name'], allowed_oidcs, "velero", "velero-server", mode=trust_mode)
    if ctx_src: run_pre_flight_irsa(ctx_src, allowed_oidcs, mode=trust_mode)
    
    print(f"\n--- 🚀 FASE ORIGEM (Backup) ---")
    install_velero(ctx_src)
    backup_istio_to_s3(ctx_src, bk)
    
    print(f"💾 Criando Backup Velero: {bk}")
    try:
        run_shell(f"velero backup create {bk} --exclude-namespaces {','.join(SYSTEM_NAMESPACES)} --exclude-resources {EXCLUDE_RESOURCES} --wait")
        print("⏳ Aguardando 60s para consolidação...")
        time.sleep(60)
        print(f"✅ Backup '{bk}' concluído.")
        return bk
    except SystemExit: print("❌ Backup falhou."); sys.exit(1)

def execute_restore_flow(ctx_dst, bk_name, allowed_oidcs, trust_mode):
    configure_irsa_trust(CONFIG['role_name'], allowed_oidcs, "velero", "velero-server", mode=trust_mode)
    print(f"\n--- 🛬 FASE DESTINO (Restore) ---")
    install_velero(ctx_dst)
    
    if wait_for_backup_sync(bk_name):
        print(f"♻️  Restaurando Aplicações '{bk_name}'...")
        run_shell(f"velero restore create --from-backup {bk_name} --existing-resource-policy update --exclude-resources {EXCLUDE_RESOURCES} --wait")
        restore_istio_from_s3(ctx_dst, bk_name)
        print("\n🎉 Restore finalizado com sucesso!")
    else: print("\n⛔ Restore abortado."); sys.exit(1)

# --- MAIN ---
def main():
    cwd = os.getcwd()
    os.environ["HOME"] = cwd
    os.environ["KUBECONFIG"] = os.path.join(cwd, "kube_config")
    
    load_config()
    validate_bucket(CONFIG['bucket_name'])
    CONFIG['role_name'] = extract_and_validate_role(CONFIG['role_arn'])
    ensure_role_permissions(CONFIG['role_name'], CONFIG['bucket_name'])
    generate_velero_values(CONFIG['bucket_name'], CONFIG['role_arn'], CONFIG['region'])

    ctx_src, ctx_dst = None, None
    oidc_src, oidc_dst = None, None
    target_oidcs = []

    if CONFIG['cluster_src']:
        ctx_src = setup_kube_context(CONFIG['cluster_src'])
        oidc_src = get_cluster_oidc(CONFIG['cluster_src'])
        target_oidcs.append(oidc_src)

    if CONFIG['cluster_dst']:
        ctx_dst = setup_kube_context(CONFIG['cluster_dst'])
        oidc_dst = get_cluster_oidc(CONFIG['cluster_dst'])
        target_oidcs.append(oidc_dst)

    mode = CONFIG['mode']
    trust_mode = 'replace' if mode == 'FULL_MIGRATION' else 'append'
    
    if mode == 'BACKUP_ONLY':
        execute_backup_flow(ctx_src, target_oidcs, trust_mode)
    elif mode == 'RESTORE_ONLY':
        execute_restore_flow(ctx_dst, CONFIG['restore_backup_name'], target_oidcs, trust_mode)
    elif mode == 'FULL_MIGRATION':
        bk_name = execute_backup_flow(ctx_src, target_oidcs, trust_mode)
        execute_restore_flow(ctx_dst, bk_name, target_oidcs, trust_mode)

    print("\n✅ Processo finalizado.")

if __name__ == "__main__":
    main()
