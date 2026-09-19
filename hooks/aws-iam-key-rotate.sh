#!/bin/sh
# sec rotate hook: rotate an IAM user's access key. The secret stored under
# SEC_NAME is the *secret access key*; the access key id lives in a sibling
# secret named ${SEC_NAME}_ID (kept in step by this hook via `sec set`).
# Usage: IAM_USER=deploy sec rotate AWS_SECRET_ACCESS_KEY --hook hooks/aws-iam-key-rotate.sh  (value on stdin is ignored; AWS mints it)
set -eu
: "${IAM_USER:?set IAM_USER}"
out=$(aws iam create-access-key --user-name "$IAM_USER" --output json)
new_id=$(printf '%s' "$out" | sed -n 's/.*"AccessKeyId": *"\([^"]*\)".*/\1/p')
new_secret=$(printf '%s' "$out" | sed -n 's/.*"SecretAccessKey": *"\([^"]*\)".*/\1/p')
printf '%s' "$new_id" | sec set "${SEC_NAME}_ID" >/dev/null
printf '%s' "$new_secret" | sec set "$SEC_NAME" >/dev/null
old_id=$(aws iam list-access-keys --user-name "$IAM_USER" --query "AccessKeyMetadata[?AccessKeyId!='$new_id'].AccessKeyId" --output text)
for k in $old_id; do aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$k"; done
echo "aws: new access key issued for $IAM_USER, old key(s) deleted"
