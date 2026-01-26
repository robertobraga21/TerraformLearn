import boto3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import csv
from tkinter import font
from botocore.exceptions import NoCredentialsError, NoRegionError, ProfileNotFound

# --- LÓGICA AWS (sem alterações) ---
def listar_todos_recursos(tagging_client, output_queue, results_list, resource_types=None):
    try:
        output_queue.put("INFO: Listando todos os recursos na conta (pode demorar)...")
        recursos_encontrados = 0
        params = {}
        if resource_types:
            params['ResourceTypeFilters'] = resource_types
        paginator = tagging_client.get_paginator('get_resources')
        pages = paginator.paginate(**params)
        for page in pages:
            for resource in page['ResourceTagMappingList']:
                arn = resource['ResourceARN']
                results_list.append(arn)
                tags_str = ", ".join([f"{t['Key']}='{t['Value']}'" for t in resource['Tags']])
                output_queue.put(f"  - ARN: {arn}")
                output_queue.put(f"    Tags: [{tags_str}]")
                recursos_encontrados += 1
        if recursos_encontrados == 0:
            output_queue.put("INFO: Nenhum recurso foi encontrado para os filtros selecionados.")
        output_queue.put(f"\nSUCESSO: Busca concluída. Total de {recursos_encontrados} recurso(s) encontrado(s).\n")
    except NoCredentialsError:
        output_queue.put("ERRO DE CREDENCIAIS: Não foi possível autenticar. Verifique se está logado via 'aws sso login' ou se suas chaves estão configuradas.")
    except Exception as e:
        output_queue.put(f"ERRO: Falha ao listar todos os recursos: {e}\n")

def buscar_recursos_com_tag(tagging_client, chave_tag, valor_tag, output_queue, results_list, resource_types=None):
    try:
        output_queue.put(f"INFO: Buscando recursos com a tag '{chave_tag}'...")
        recursos_encontrados = 0
        params = {'TagFilters': [{'Key': chave_tag}]}
        if valor_tag:
            params['TagFilters'][0]['Values'] = [valor_tag]
        if resource_types:
            params['ResourceTypeFilters'] = resource_types
        paginator = tagging_client.get_paginator('get_resources')
        pages = paginator.paginate(**params)
        for page in pages:
            for resource in page['ResourceTagMappingList']:
                arn = resource['ResourceARN']
                results_list.append(arn)
                output_queue.put(f"  - {arn}")
                recursos_encontrados += 1
        if recursos_encontrados == 0:
            output_queue.put("INFO: Nenhum recurso encontrado para os filtros selecionados.")
        output_queue.put(f"\nSUCESSO: Busca concluída. Total de {recursos_encontrados} recurso(s) encontrado(s).\n")
    except NoCredentialsError:
        output_queue.put("ERRO DE CREDENCIAIS: Não foi possível autenticar. Verifique suas credenciais.")
    except Exception as e:
        output_queue.put(f"ERRO: Falha ao buscar recursos: {e}\n")

def buscar_recursos_sem_tag(tagging_client, chave_tag, output_queue, results_list, resource_types=None):
    try:
        output_queue.put(f"INFO: Buscando recursos SEM a tag '{chave_tag}'...")
        params = {}
        if resource_types:
            params['ResourceTypeFilters'] = resource_types
        recursos_com_a_tag_set = set()
        params_com_tag = params.copy()
        params_com_tag['TagFilters'] = [{'Key': chave_tag}]
        paginator_com_tag = tagging_client.get_paginator('get_resources')
        pages_com_tag = paginator_com_tag.paginate(**params_com_tag)
        for page in pages_com_tag:
            for resource in page['ResourceTagMappingList']:
                recursos_com_a_tag_set.add(resource['ResourceARN'])
        recursos_encontrados_sem_a_tag = 0
        paginator_todos = tagging_client.get_paginator('get_resources')
        pages_todos = paginator_todos.paginate(**params)
        for page in pages_todos:
            for resource in page['ResourceTagMappingList']:
                arn = resource['ResourceARN']
                if arn not in recursos_com_a_tag_set:
                    results_list.append(arn)
                    output_queue.put(f"  - {arn}")
                    recursos_encontrados_sem_a_tag += 1
        if recursos_encontrados_sem_a_tag == 0:
            output_queue.put("INFO: Nenhum recurso encontrado para os filtros selecionados.")
        output_queue.put(f"\nSUCESSO: Busca concluída. Total de {recursos_encontrados_sem_a_tag} recurso(s) encontrado(s).\n")
    except Exception as e:
        output_queue.put(f"ERRO: Falha ao buscar recursos sem a tag: {e}\n")

def adicionar_ou_editar_tags(tagging_client, recurso_arn, tags_para_adicionar, output_queue):
    try:
        output_queue.put(f"INFO: Adicionando/editando tags no recurso: {recurso_arn}...")
        tagging_client.tag_resources(ResourceARNList=[recurso_arn], Tags=tags_para_adicionar)
        output_queue.put("SUCESSO: Tags aplicadas com sucesso!\n")
    except Exception as e:
        output_queue.put(f"ERRO: Falha ao aplicar tags em {recurso_arn}: {e}\n")

def remover_tags(tagging_client, recurso_arn, chaves_das_tags_para_remover, output_queue):
    try:
        output_queue.put(f"INFO: Removendo tags do recurso: {recurso_arn}...")
        tagging_client.untag_resources(ResourceARNList=[recurso_arn], TagKeys=chaves_das_tags_para_remover)
        output_queue.put("SUCESSO: Tags removidas com sucesso!\n")
    except Exception as e:
        output_queue.put(f"ERRO: Falha ao remover tags de {recurso_arn}: {e}\n")

# --- Dicionário de Serviços ---
SERVICE_FILTERS = {
    "Todos os Serviços": None, "Amplify": ["amplify:app"], "API Gateway": ["apigateway:restapis", "apigateway:stages"], "AppStream 2.0": ["appstream:fleet"], "Athena": ["athena:workgroup"], "Certificate Manager (ACM)": ["acm:certificate"], "CloudFormation": ["cloudformation:stack"], "CloudFront": ["cloudfront:distribution", "cloudfront:streaming-distribution"], "CloudTrail": ["cloudtrail:trail"], "CloudWatch": ["cloudwatch:alarm"], "CodeBuild": ["codebuild:project"], "CodeCommit": ["codecommit:repository"], "CodeDeploy": ["codedeploy:application"], "CodePipeline": ["codepipeline:pipeline"], "Cognito": ["cognito-idp:userpool"], "Config": ["config:config-rule"], "DataSync": ["datasync:task"], "Direct Connect": ["directconnect:dxconn", "directconnect:dxlag"], "DynamoDB": ["dynamodb:table"], "EC2 - AMIs": ["ec2:image"], "EC2 - Elastic IPs": ["ec2:elastic-ip"], "EC2 - Grupos de Segurança": ["ec2:security-group"], "EC2 - Instâncias": ["ec2:instance"], "EC2 - Internet Gateways": ["ec2:internet-gateway"], "EC2 - Key Pairs": ["ec2:key-pair"], "EC2 - Launch Templates": ["ec2:launch-template"], "EC2 - NAT Gateways": ["ec2:natgateway"], "EC2 - Network ACLs": ["ec2:network-acl"], "EC2 - Route Tables": ["ec2:route-table"], "EC2 - Snapshots": ["ec2:snapshot"], "EC2 - Subnets": ["ec2:subnet"], "EC2 - Volumes EBS": ["ec2:volume"], "EC2 - VPCs": ["ec2:vpc"], "ECS - Clusters": ["ecs:cluster"], "ECS - Serviços": ["ecs:service"], "ECS - Tarefas": ["ecs:task"], "EFS - Sistemas de Arquivos": ["efs:file-system"], "EKS - Clusters": ["eks:cluster"], "ElastiCache": ["elasticache:cluster"], "Elastic Beanstalk": ["elasticbeanstalk:application", "elasticbeanstalk:environment"], "Elastic Load Balancing": ["elasticloadbalancing:loadbalancer", "elasticloadbalancing:targetgroup"], "EMR - Clusters": ["elasticmapreduce:cluster"], "Glacier": ["glacier:vault"], "Glue": ["glue:job", "glue:trigger"], "IAM - Papéis (Roles)": ["iam:role"], "IAM - Usuários": ["iam:user"], "Kinesis": ["kinesis:stream"], "KMS": ["kms:key"], "Lambda": ["lambda:function"], "Lightsail": ["lightsail:instance", "lightsail:disk"], "RDS - Bancos de Dados": ["rds:db"], "RDS - Snapshots de BD": ["rds:snapshot"], "Redshift": ["redshift:cluster"], "Route 53": ["route53:healthcheck", "route53:hostedzone"], "S3 - Buckets": ["s3"], "SageMaker": ["sagemaker:notebook-instance"], "Secrets Manager": ["secretsmanager:secret"], "Service Catalog": ["servicecatalog:product"], "SES": ["ses:identity"], "SNS": ["sns:topic"], "SQS": ["sqs:queue"], "Storage Gateway": ["storagegateway:gateway"], "WAF": ["waf:webacl", "waf-regional:webacl"]
}

# --- INTERFACE GRÁFICA (GUI) COM TKINTER ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gerenciador de Tags AWS v10.3 (Corrigido)")
        self.geometry("900x750")
        self.output_queue = queue.Queue()
        self.last_listed_arns = []
        
        self.account_id_var = tk.StringVar(value="Desconectado")
        self.account_alias_var = tk.StringVar(value="Selecione um perfil para conectar")
        self.service_filter_var = tk.StringVar()
        self.profile_var = tk.StringVar()

        self.tagging_client = None
        self.sts_client = None
        self.iam_client = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)
        
        self._create_account_info_frame()
        self._create_controls_frame()
        self._create_bulk_actions_frame()
        self._create_results_frame()
        self.after(100, self.process_queue)
        
        self.after(100, self._initialize_aws_connection)

    def _initialize_aws_connection(self):
        self._write_to_results("INFO: Procurando por perfis AWS configurados...")
        try:
            profiles = boto3.session.Session().available_profiles
            if not profiles:
                self.profile_menu['values'] = ["Nenhum perfil encontrado"]
                self.profile_var.set("Nenhum perfil encontrado")
                self.profile_menu.config(state="disabled")
                self._write_to_results("ERRO: Nenhum perfil AWS encontrado.")
                messagebox.showerror("Erro de Configuração", "Nenhum perfil AWS foi encontrado. Configure o AWS CLI com 'aws configure' ou 'aws sso configure' antes de usar a ferramenta.")
                return
            
            self.profile_menu['values'] = profiles
            if 'default' in profiles:
                self.profile_var.set('default')
            else:
                self.profile_var.set(profiles[0])
            
            self._on_profile_change()

        except Exception as e:
            messagebox.showerror("Erro Crítico na Inicialização", f"Ocorreu um erro inesperado ao tentar ler a configuração da AWS: {e}")
            self.destroy()

    def _create_account_info_frame(self):
        frame = ttk.LabelFrame(self, text="Sessão e Conta AWS", padding="10")
        frame.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
        ttk.Label(frame, text="Perfil AWS:", font="-weight bold").grid(row=0, column=0, sticky="w")
        self.profile_menu = ttk.Combobox(frame, textvariable=self.profile_var, state="readonly", width=25)
        self.profile_menu.grid(row=0, column=1, sticky="w", padx=5)
        self.profile_menu.bind("<<ComboboxSelected>>", self._on_profile_change)
        ttk.Label(frame, text="ID da Conta:", font="-weight bold").grid(row=1, column=0, sticky="w", pady=(5,0))
        ttk.Label(frame, textvariable=self.account_id_var).grid(row=1, column=1, sticky="w", padx=5, pady=(5,0))
        ttk.Label(frame, text="Nome (Alias):", font="-weight bold").grid(row=2, column=0, sticky="w")
        ttk.Label(frame, textvariable=self.account_alias_var).grid(row=2, column=1, sticky="w", padx=5)
        frame.grid_columnconfigure(1, weight=1)

    def _on_profile_change(self, event=None):
        selected_profile = self.profile_var.get()
        self._clear_results()
        self._set_buttons_state("disabled")
        self._write_to_results(f"\n--- Trocando para o perfil: {selected_profile} ---")
        thread = threading.Thread(target=self._initialize_boto3_session, args=(selected_profile,), daemon=True)
        thread.start()
        ### CORREÇÃO: Adicionada a chamada para monitorar a thread de inicialização ###
        self.monitor_thread(thread)

    def _initialize_boto3_session(self, profile_name):
        try:
            session = boto3.Session(profile_name=profile_name)
            region = session.region_name
            if not region:
                self.output_queue.put(f"ERRO: O perfil '{profile_name}' não tem uma região configurada. Por favor, configure-a no arquivo ~/.aws/config.")
                self.account_id_var.set("Falha")
                self.account_alias_var.set("Sem região")
                return

            self.tagging_client = session.client('resourcegroupstaggingapi', region_name=region)
            self.sts_client = session.client('sts', region_name=region)
            self.iam_client = session.client('iam', region_name=region)
            
            self._load_account_details()
        except (ProfileNotFound, NoCredentialsError) as e:
            self.output_queue.put(f"ERRO: {e}. Se for um perfil SSO, tente executar 'aws sso login --profile {profile_name}' no terminal.")
            self.account_id_var.set("Falha na conexão")
            self.account_alias_var.set("Verifique o perfil")
        except Exception as e:
            self.output_queue.put(f"ERRO ao iniciar sessão com o perfil '{profile_name}': {e}")
            self.account_id_var.set("Falha na conexão")
            self.account_alias_var.set("Verifique o perfil")

    def _load_account_details(self):
        try:
            account_id = self.sts_client.get_caller_identity()['Account']
            self.account_id_var.set(account_id)
            aliases = self.iam_client.list_account_aliases()['AccountAliases']
            if aliases: self.account_alias_var.set(aliases[0])
            else: self.account_alias_var.set("Nenhum alias configurado")
            self.output_queue.put(f"INFO: Conectado com sucesso à conta {account_id}.")
        except Exception as e:
            self.account_id_var.set("Erro ao obter ID")
            self.account_alias_var.set("Falha na conexão")
            self.output_queue.put(f"ERRO: Não foi possível obter detalhes da conta. Verifique suas permissões.\nDetalhes: {e}")

    def _create_controls_frame(self):
        frame = ttk.LabelFrame(self, text="Ações e Filtros", padding="10")
        frame.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        ttk.Label(frame, text="Ação:").grid(row=0, column=0, padx=(0, 5), sticky="w")
        self.action_var = tk.StringVar()
        actions = ["Listar todos os recursos", "Buscar com Tag", "Buscar sem Tag", "Adicionar/Editar Tags", "Remover Tags"]
        action_menu = ttk.Combobox(frame, textvariable=self.action_var, values=actions, state="readonly", width=25)
        action_menu.grid(row=0, column=1, padx=5, sticky="ew")
        action_menu.set(actions[0])
        ttk.Label(frame, text="Filtrar por Serviço:").grid(row=0, column=2, padx=(10, 5), sticky="w")
        sorted_services = ["Todos os Serviços"] + sorted([s for s in SERVICE_FILTERS if s != "Todos os Serviços"])
        service_menu = ttk.Combobox(frame, textvariable=self.service_filter_var, values=sorted_services, state="readonly", width=25)
        service_menu.grid(row=0, column=3, padx=5, sticky="ew")
        service_menu.set("Todos os Serviços")
        ttk.Label(frame, text="Chave da Tag:").grid(row=1, column=0, padx=(0, 5), pady=5, sticky="w")
        self.key_entry = ttk.Entry(frame)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(frame, text="Valor da Tag:").grid(row=1, column=2, padx=(10, 5), pady=5, sticky="w")
        self.value_entry = ttk.Entry(frame)
        self.value_entry.grid(row=1, column=3, padx=5, pady=5, sticky="ew")
        ttk.Label(frame, text="ARN do Recurso:").grid(row=2, column=0, padx=(0, 5), pady=5, sticky="w")
        self.arn_entry = ttk.Entry(frame)
        self.arn_entry.grid(row=2, column=1, columnspan=3, padx=5, pady=5, sticky="ew")
        buttons_frame = ttk.Frame(frame)
        buttons_frame.grid(row=3, column=0, columnspan=4, pady=10)
        self.execute_button = ttk.Button(buttons_frame, text="Executar Ação", command=self.start_action_thread)
        self.execute_button.pack(side="left", padx=5)
        self.clear_button = ttk.Button(buttons_frame, text="Limpar Lista", command=self._clear_results)
        self.clear_button.pack(side="left", padx=5)
        self.bulk_button = ttk.Button(buttons_frame, text="Carregar Planilha...", command=self.start_bulk_tag_thread)
        self.bulk_button.pack(side="left", padx=5)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(3, weight=1)

    def _create_bulk_actions_frame(self):
        frame = ttk.LabelFrame(self, text="Ações em Massa (Sobre a Lista de Resultados)", padding="10")
        frame.grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 10))
        default_font = font.nametofont("TkDefaultFont")
        help_font = font.Font(family=default_font.cget("family"), size=default_font.cget("size") - 1, slant="italic")
        help_text = "Use os botões abaixo para aplicar ou remover uma tag em TODOS os recursos listados na área de resultados."
        ttk.Label(frame, text=help_text, font=help_font, foreground="gray").pack(pady=(0, 10))
        buttons_sub_frame = ttk.Frame(frame)
        buttons_sub_frame.pack()
        self.apply_to_list_button = ttk.Button(buttons_sub_frame, text="Aplicar Tag à Lista", command=self.start_apply_to_list_thread, state="disabled")
        self.apply_to_list_button.pack(side="left", padx=5)
        self.remove_from_list_button = ttk.Button(buttons_sub_frame, text="Remover Tag da Lista", command=self.start_remove_from_list_thread, state="disabled")
        self.remove_from_list_button.pack(side="left", padx=5)

    def _create_results_frame(self):
        frame = ttk.Frame(self, padding="10")
        frame.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        self.results_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, state="disabled")
        self.results_text.grid(row=0, column=0, sticky="nsew")

    def _clear_results(self):
        self.results_text.config(state="normal"); self.results_text.delete('1.0', tk.END); self.results_text.config(state="disabled")
        self.last_listed_arns.clear(); self.apply_to_list_button.config(state="disabled"); self.remove_from_list_button.config(state="disabled")

    def _set_buttons_state(self, state):
        self.execute_button.config(state=state)
        self.clear_button.config(state=state)
        self.bulk_button.config(state=state)
        if state == "disabled":
            self.apply_to_list_button.config(state="disabled")
            self.remove_from_list_button.config(state="disabled")

    def monitor_thread(self, thread):
        if thread.is_alive():
            self.after(100, lambda: self.monitor_thread(thread))
        else:
            self._set_buttons_state("normal")
            if self.last_listed_arns:
                self.apply_to_list_button.config(state="normal")
                self.remove_from_list_button.config(state="normal")
    
    def _write_to_results(self, message):
        self.results_text.config(state="normal"); self.results_text.insert(tk.END, message + "\n"); self.results_text.config(state="disabled"); self.results_text.see(tk.END)

    def process_queue(self):
        try:
            while True:
                message = self.output_queue.get_nowait(); self._write_to_results(message)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.process_queue)
            
    def _validate_arns_existence(self, arns_to_check):
        if not arns_to_check or not self.tagging_client: return set()
        found_arns = set()
        for i in range(0, len(arns_to_check), 100):
            batch = arns_to_check[i:i + 100]
            try:
                response = self.tagging_client.get_resources(ResourceARNList=batch)
                for mapping in response.get('ResourceTagMappingList', []):
                    found_arns.add(mapping['ResourceARN'])
            except Exception as e:
                self.output_queue.put(f"AVISO: Ocorreu um erro durante a validação de ARNs: {e}")
        return found_arns
        
    def start_action_thread(self):
        self.last_listed_arns.clear()
        self.apply_to_list_button.config(state="disabled")
        self.remove_from_list_button.config(state="disabled")
        action = self.action_var.get(); key = self.key_entry.get().strip(); value = self.value_entry.get().strip(); arn = self.arn_entry.get().strip()
        selected_service = self.service_filter_var.get(); resource_types = SERVICE_FILTERS.get(selected_service)
        if not self.tagging_client: messagebox.showerror("Erro de Sessão", "A sessão AWS não foi iniciada. Selecione um perfil válido."); return
        if action != "Listar todos os recursos":
            if "Buscar" in action and not key: messagebox.showerror("Erro de Entrada", "A 'Chave da Tag' é obrigatória."); return
            if ("Adicionar" in action or "Remover" in action) and not arn: messagebox.showerror("Erro de Entrada", "O 'ARN do Recurso' é obrigatório."); return
            if "Adicionar" in action and not key: messagebox.showerror("Erro de Entrada", "A 'Chave da Tag' é obrigatória."); return
            if "Remover" in action and not key: messagebox.showerror("Erro de Entrada", "A 'Chave da Tag' é obrigatória."); return
        if action in ["Adicionar/Editar Tags", "Remover Tags"]:
            current_account_id = self.account_id_var.get()
            if not current_account_id.isdigit(): messagebox.showerror("Erro Crítico", "Não foi possível validar o ID da conta da sessão atual."); return
            is_s3 = arn.startswith('arn:aws:s3:::')
            if not is_s3:
                try:
                    arn_account_id = arn.split(':')[4]
                    if arn_account_id != current_account_id: messagebox.showerror("Falha de Validação", f"O ARN pertence a outra conta ({arn_account_id})."); return
                except IndexError: messagebox.showerror("Erro de ARN", "O ARN informado parece ser inválido."); return
            self._write_to_results(f"INFO: Validando existência do recurso {arn}...")
            if not self._validate_arns_existence([arn]):
                messagebox.showerror("Recurso Não Encontrado", "O recurso com o ARN informado não foi encontrado."); self._write_to_results(f"ERRO: Recurso com ARN {arn} não encontrado."); return
            self._write_to_results("INFO: Recurso encontrado. Prosseguindo...")
        self._set_buttons_state("disabled")
        self._write_to_results(f"--- Iniciando Ação: {action} ---")
        target_func, args = None, ()
        if "Listar" in action or "Buscar" in action:
            if action == "Listar todos os recursos": args = (self.tagging_client, self.output_queue, self.last_listed_arns, resource_types); target_func = listar_todos_recursos
            elif action == "Buscar com Tag": args = (self.tagging_client, key, value, self.output_queue, self.last_listed_arns, resource_types); target_func = buscar_recursos_com_tag
            elif action == "Buscar sem Tag": args = (self.tagging_client, key, self.output_queue, self.last_listed_arns, resource_types); target_func = buscar_recursos_sem_tag
        else:
            if action == "Adicionar/Editar Tags": tags_to_add = {key: value}; args = (self.tagging_client, arn, tags_to_add, self.output_queue); target_func = adicionar_ou_editar_tags
            elif action == "Remover Tags": keys_to_remove = [k.strip() for k in key.split(',')]; args = (self.tagging_client, arn, keys_to_remove, self.output_queue); target_func = remover_tags
        if not target_func: self._write_to_results("ERRO: Ação desconhecida."); self._set_buttons_state("normal"); return
        thread = threading.Thread(target=target_func, args=args); thread.daemon = True; thread.start(); self.monitor_thread(thread)

    def _remove_tags_in_batches(self, arns, tag_key_to_remove, output_queue):
        output_queue.put(f"\n--- Removendo a tag com chave '{tag_key_to_remove}' de {len(arns)} recurso(s) ---")
        for i in range(0, len(arns), 20):
            batch = arns[i:i + 20]
            try:
                self.tagging_client.untag_resources(ResourceARNList=batch, TagKeys=[tag_key_to_remove]); output_queue.put(f"Lote {i//20+1}: SUCESSO.")
            except Exception as e:
                output_queue.put(f"Lote {i//20+1}: ERRO - {e}")
        output_queue.put("\n--- Remoção de tags em massa concluída. ---")

    def start_remove_from_list_thread(self):
        tag_key = self.key_entry.get().strip()
        if not self.last_listed_arns: messagebox.showwarning("Ação Inválida", "Nenhum recurso listado."); return
        if not tag_key: messagebox.showwarning("Entrada Inválida", "O campo 'Chave da Tag' não pode estar vazio."); return
        self._set_buttons_state("disabled")
        thread = threading.Thread(target=self._remove_tags_in_batches, args=(self.last_listed_arns, tag_key, self.output_queue))
        thread.daemon = True; thread.start(); self.monitor_thread(thread)
        
    def _apply_tags_in_batches(self, arns, tag_key, tag_value, output_queue):
        output_queue.put(f"\n--- Aplicando a tag '{tag_key}={tag_value}' em {len(arns)} recurso(s) ---")
        for i in range(0, len(arns), 20):
            batch = arns[i:i + 20]
            try:
                self.tagging_client.tag_resources(ResourceARNList=batch, Tags={tag_key: tag_value}); output_queue.put(f"Lote {i//20+1}: SUCESSO.")
            except Exception as e:
                output_queue.put(f"Lote {i//20+1}: ERRO - {e}")
        output_queue.put("\n--- Aplicação de tags em massa concluída. ---")

    def start_apply_to_list_thread(self):
        tag_key, tag_value = self.key_entry.get().strip(), self.value_entry.get().strip()
        if not self.last_listed_arns: messagebox.showwarning("Ação Inválida", "Nenhum recurso listado."); return
        if not tag_key: messagebox.showwarning("Entrada Inválida", "O campo 'Chave da Tag' não pode estar vazio."); return
        self._set_buttons_state("disabled")
        thread = threading.Thread(target=self._apply_tags_in_batches, args=(self.last_listed_arns, tag_key, tag_value, self.output_queue))
        thread.daemon = True; thread.start(); self.monitor_thread(thread)
            
    def _process_csv_and_tag(self, filepath, output_queue):
        current_account_id = self.account_id_var.get()
        if not current_account_id.isdigit():
            output_queue.put("ERRO CRÍTICO: Não foi possível obter o ID da conta atual para validação.\nAção cancelada."); return
        try:
            output_queue.put("INFO: Lendo e validando o arquivo CSV...")
            rows_to_process = []; arns_to_validate = []
            with open(filepath, mode='r', encoding='utf-8-sig', newline='') as infile:
                dialect = csv.Sniffer().sniff(infile.read(1024)); infile.seek(0)
                reader = csv.DictReader(infile, dialect=dialect)
                if not {'arn', 'tags'}.issubset(reader.fieldnames):
                    output_queue.put("ERRO: O arquivo CSV deve conter as colunas 'arn' e 'tags'."); return
                for i, row in enumerate(reader, 1):
                    arn = row.get('arn', '').strip()
                    if not arn: continue
                    is_s3 = arn.startswith('arn:aws:s3:::'); is_valid = True
                    if not is_s3:
                        try:
                            arn_account_id = arn.split(':')[4]
                            if arn_account_id != current_account_id:
                                output_queue.put(f"AVISO (Linha {i+1}): ARN da conta {arn_account_id} ignorado."); is_valid = False
                        except IndexError:
                            output_queue.put(f"AVISO (Linha {i+1}): ARN '{arn}' inválido e ignorado."); is_valid = False
                    if is_valid:
                        rows_to_process.append(row); arns_to_validate.append(arn)
            if not rows_to_process:
                output_queue.put("ERRO: Nenhum ARN válido para a conta atual foi encontrado no arquivo."); return
            output_queue.put(f"\nINFO: Validando a existência de {len(arns_to_validate)} recurso(s)...")
            existing_arns = self._validate_arns_existence(arns_to_validate)
            output_queue.put(f"INFO: {len(existing_arns)} recurso(s) encontrados e válidos.")
            output_queue.put("\nINFO: Iniciando aplicação de tags...")
            for row in rows_to_process:
                arn, tags_string = row['arn'], row['tags']
                if arn not in existing_arns:
                    output_queue.put(f"AVISO: Recurso com ARN '{arn[:40]}...' não foi encontrado e será ignorado."); continue
                tags_to_apply = {}; malformed = False
                for tag_pair in tags_string.split('|'):
                    if '=' not in tag_pair: malformed = True; break
                    key, value = tag_pair.split('=', 1)
                    if key.strip(): tags_to_apply[key.strip()] = value.strip()
                if malformed or not tags_to_apply:
                    output_queue.put(f"ERRO: 'tags' mal formatada para o ARN '{arn}'. Use 'chave=valor|chave=valor'."); continue
                output_queue.put(f"INFO: Aplicando {len(tags_to_apply)} tag(s) em {arn}...")
                try:
                    self.tagging_client.tag_resources(ResourceARNList=[arn], Tags=tags_to_apply)
                    output_queue.put(f"  -> SUCESSO!")
                except Exception as e:
                    output_queue.put(f"  -> ERRO: {e}")
        except Exception as e:
            output_queue.put(f"ERRO GERAL ao processar o arquivo: {e}")
        finally:
            output_queue.put("\n--- Processamento da planilha concluído. ---")
            
    def start_bulk_tag_thread(self):
        filepath = filedialog.askopenfilename(title="Selecione a planilha de tags", filetypes=(("Arquivos CSV", "*.csv"), ("Todos os arquivos", "*.*")))
        if not filepath: return
        self._set_buttons_state("disabled"); self._write_to_results(f"--- Iniciando aplicação de tags com base no arquivo: {filepath}")
        thread = threading.Thread(target=self._process_csv_and_tag, args=(filepath, self.output_queue))
        thread.daemon = True; thread.start(); self.monitor_thread(thread)

if __name__ == "__main__":
    app = App()
    app.mainloop()
