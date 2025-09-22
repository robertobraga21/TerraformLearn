#!/bin/bash

# Substitua pelo ID da sua instância
INSTANCE_ID="i-0123456789abcdef0"

echo "Procurando Target Groups para a instância: $INSTANCE_ID..."

# 1. Pega o ARN de todos os Target Groups na sua região configurada
TARGET_GROUP_ARNS=$(aws elbv2 describe-target-groups --query 'TargetGroups[*].TargetGroupArn' --output text)

if [ -z "$TARGET_GROUP_ARNS" ]; then
  echo "Nenhum Target Group encontrado na região."
  exit 1
fi

# 2. Itera sobre cada Target Group e verifica se a instância está registrada
FOUND_TGS=()
for TG_ARN in $TARGET_GROUP_ARNS; do
  HEALTH_CHECK=$(aws elbv2 describe-target-health --target-group-arn "$TG_ARN" \
    --query "TargetHealthDescriptions[?Target.Id=='$INSTANCE_ID']")
  
  # 3. Se o resultado não for vazio, a instância pertence a este TG
  if [ ! -z "$HEALTH_CHECK" ] && [ "$HEALTH_CHECK" != "[]" ]; then
    echo "--------------------------------------------------------"
    echo "✅ Instância encontrada no Target Group:"
    echo "   ARN: $TG_ARN"
    FOUND_TGS+=("$TG_ARN")
  fi
done

if [ ${#FOUND_TGS[@]} -eq 0 ]; then
  echo "--------------------------------------------------------"
  echo "❌ A instância $INSTANCE_ID não foi encontrada em nenhum Target Group."
  exit 1
fi







# Substitua pelo ARN do Target Group encontrado no passo anterior
TARGET_GROUP_ARN="arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/meu-target-group/..."

echo "Procurando Load Balancers para o Target Group: $TARGET_GROUP_ARN"

# 1. Descreve todas as regras de todos os listeners
# 2. Usa 'jq' para filtrar a regra que tem uma ação apontando para o nosso Target Group
LISTENER_RULE=$(aws elbv2 describe-rules --query "Rules[?Actions[?TargetGroupArn=='$TARGET_GROUP_ARN']]" --output json)

# 3. Extrai o ARN do Listener a partir da regra encontrada
LISTENER_ARN=$(echo $LISTENER_RULE | jq -r '.[0].ListenerArn')

if [ -z "$LISTENER_ARN" ] || [ "$LISTENER_ARN" == "null" ]; then
    echo "--------------------------------------------------------"
    echo "❌ Nenhuma regra de Listener encontrada para este Target Group."
    echo "Verificando ações padrão dos Listeners (caso mais simples)..."

    # Fallback: Verifica as ações padrão dos Listeners
    LOAD_BALANCER_ARN=$(aws elbv2 describe-listeners \
        --query "Listeners[?DefaultActions[?TargetGroupArn=='$TARGET_GROUP_ARN']].LoadBalancerArn" \
        --output text)
else
    # 4. Com o ARN do Listener, descreve o Listener para obter o ARN do Load Balancer
    LOAD_BALANCER_ARN=$(aws elbv2 describe-listeners --listener-arns "$LISTENER_ARN" \
        --query 'Listeners[0].LoadBalancerArn' --output text)
fi


if [ ! -z "$LOAD_BALANCER_ARN" ]; then
    echo "--------------------------------------------------------"
    echo "✅ Target Group associado ao Load Balancer:"
    echo "   ARN: $LOAD_BALANCER_ARN"

    # Opcional: Obter mais detalhes do Load Balancer, como o DNS Name
    LB_DETAILS=$(aws elbv2 describe-load-balancers --load-balancer-arns "$LOAD_BALANCER_ARN")
    LB_DNS_NAME=$(echo $LB_DETAILS | jq -r '.LoadBalancers[0].DNSName')
    LB_NAME=$(echo $LB_DETAILS | jq -r '.LoadBalancers[0].LoadBalancerName')
    echo "   Nome: $LB_NAME"
    echo "   DNS: $LB_DNS_NAME"
    echo "--------------------------------------------------------"
else
    echo "--------------------------------------------------------"
    echo "❌ Nenhum Load Balancer encontrado para o Target Group: $TARGET_GROUP_ARN"
    echo "--------------------------------------------------------"
fi

