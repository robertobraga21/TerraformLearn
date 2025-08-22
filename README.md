BUCKET="meu-bucket"
PREFIX="minha/pasta/"       # a “pasta” dentro do bucket
START="2025-08-21T00:00:00+00:00"  # início (UTC)
END="2025-08-22T00:00:00+00:00"    # fim (UTC)
DEST="./downloads"

mkdir -p "$DEST"

aws s3api list-objects-v2 \
  --bucket "$BUCKET" \
  --prefix "$PREFIX" \
  --page-size 1000 \
  --query "Contents[?LastModified>='$START' && LastModified<'$END'].Key" \
  --output text |
tr '\t' '\n' | sed '/^$/d' | while read -r key; do
  aws s3 cp "s3://$BUCKET/$key" "$DEST/"
done
