#!/bin/bash -e

KAFKA_ID=$(curl -ks https://kafka.siemens.ps.confluent.io:8090/v1/metadata/id | jq -r '.scope.clusters["kafka-cluster"]')

CONFLUENT_USERNAME=mds \
CONFLUENT_PASSWORD=7Hr5ERRu \
CONFLUENT_MDS_URL=https://kafka.siemens.ps.confluent.io:8090 \
CONFLUENT_CA_CERT_PATH=certs/sslca.pem \
confluent login

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --principal User:ccc \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --schema-registry-cluster-id schema-registry \
  --principal User:ccc \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id connect-cluster \
  --principal User:ccc \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id replicator-cluster \
  --principal User:ccc \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --schema-registry-cluster-id schema-registry \
  --principal User:registry \
  --role SecurityAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Group:schema-registry \
  --principal User:registry \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_schemas \
  --principal User:registry \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-license \
  --principal User:registry \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id connect-cluster \
  --principal User:connect \
  --role SecurityAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Group:connect-cluster \
  --principal User:connect \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-connect-configs \
  --principal User:connect \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-connect-offsets \
  --principal User:connect \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-connect-status \
  --principal User:connect \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Group:connect-secrets \
  --principal User:connect \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-connect-secrets \
  --principal User:connect \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-command \
  --principal User:connect \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id replicator-cluster \
  --principal User:connect \
  --role SecurityAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Group:replicator-cluster \
  --principal User:replicator \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-replicator-configs \
  --principal User:replicator \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-replicator-offsets \
  --principal User:replicator \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-replicator-status \
  --principal User:replicator \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Group:replicator-secrets \
  --principal User:replicator \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-replicator-secrets \
  --principal User:replicator \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:_confluent-command \
  --principal User:replicator \
  --role ResourceOwner

# See:
# https://docs.confluent.io/platform/current/security/rbac/rbac-predefined-roles.html

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --principal Group:admins \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Group:'*' \
  --principal Group:admins \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Topic:'*' \
  --principal Group:admins \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource TransactionalId:'*' \
  --principal Group:admins \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --resource Cluster:kafka-cluster \
  --principal Group:admins \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --schema-registry-cluster-id schema-registry \
  --principal Group:admins \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --schema-registry-cluster-id schema-registry \
  --resource Subject:'*' \
  --principal Group:admins \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id connect-cluster \
  --principal Group:admins \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id connect-cluster \
  --resource Connector:'*' \
  --principal Group:admins \
  --role ResourceOwner

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id replicator-cluster \
  --principal Group:admins \
  --role SystemAdmin

confluent iam rolebinding create \
  --kafka-cluster-id $KAFKA_ID \
  --connect-cluster-id replicator-cluster \
  --resource Connector:'*' \
  --principal Group:admins \
  --role ResourceOwner
