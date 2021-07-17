curl -k \
  -u sarah:ZFggjkMe \
  -d @- \
  -X PUT \
  -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  https://replicator.siemens.ps.confluent.io:8083/connectors/replicator/config << 'EOF'
{
  "connector.class": "io.confluent.connect.replicator.ReplicatorSourceConnector",

  "name": "replicator",

  "topic.whitelist": "replicator-test-source",
  "topic.rename.format": "replicator-test-target",
  "topic.auto.create": "false",

  "offset.start": "consumer",
  "offset.translator.tasks.separate": "true",
  "offset.translator.tasks.max": 0,
  "offset.timestamps.commit": "false",

  "src.kafka.bootstrap.servers": "kafka.siemens.ps.confluent.io:9093",
  "src.kafka.security.protocol": "SASL_SSL",
  "src.kafka.sasl.mechanism": "OAUTHBEARER",
  "src.kafka.sasl.jaas.config": "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required username=\"replicator\" password=\"sPD38V5O\" metadataServerUrls=\"https://kafka.siemens.ps.confluent.io:8090\" ;",
  "src.kafka.sasl.login.callback.handler.class": "io.confluent.kafka.clients.plugins.auth.token.TokenUserLoginCallbackHandler",
  "src.kafka.confluent.metadata.enable.server.urls.refresh": "false",
  "src.kafka.ssl.truststore.location": "/var/ssl/private/kafka_connect.truststore.jks",
  "src.kafka.ssl.truststore.password": "confluenttruststorepass",

  "src.consumer.bootstrap.servers": "kafka.siemens.ps.confluent.io:9093",
  "src.consumer.security.protocol": "SASL_SSL",
  "src.consumer.sasl.mechanism": "OAUTHBEARER",
  "src.consumer.sasl.jaas.config": "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required username=\"replicator\" password=\"sPD38V5O\" metadataServerUrls=\"https://kafka.siemens.ps.confluent.io:8090\" ;",
  "src.consumer.sasl.login.callback.handler.class": "io.confluent.kafka.clients.plugins.auth.token.TokenUserLoginCallbackHandler",
  "src.consumer.confluent.metadata.enable.server.urls.refresh": "false",
  "src.consumer.ssl.truststore.location": "/var/ssl/private/kafka_connect.truststore.jks",
  "src.consumer.ssl.truststore.password": "confluenttruststorepass",

  "confluent.topic.bootstrap.servers": "broker-0.demodomain:9092,broker-1.demodomain:9092,broker-2.demodomain:9092",

  "dest.kafka.bootstrap.servers": "broker-0.demodomain:9092,broker-1.demodomain:9092,broker-2.demodomain:9092",
  "dest.kafka.security.protocol": "SASL_SSL",
  "dest.kafka.sasl.mechanism": "OAUTHBEARER",
  "dest.kafka.sasl.jaas.config": "org.apache.kafka.common.security.oauthbearer.OAuthBearerLoginModule required username=\"replicator\" password=\"sPD38V5O\" metadataServerUrls=\"https://broker-0.demodomain:8090,https://broker-1.demodomain:8090,https://broker-2.demodomain:8090\";",
  "dest.kafka.sasl.login.callback.handler.class": "io.confluent.kafka.clients.plugins.auth.token.TokenUserLoginCallbackHandler",
  "dest.kafka.ssl.truststore.location": "/var/ssl/private/kafka_connect.truststore.jks",
  "dest.kafka.ssl.truststore.password": "confluenttruststorepass"

}
EOF