FROM openjdk:8-jdk-alpine
ARG JAR_FILE=target/ptai-integration-service-0.1-spring-boot.jar
ARG KEYSTORE_FILE=src/main/resources/keystore/keystore.jks
COPY ${JAR_FILE} ptai-integration-service-0.1-spring-boot.jar
COPY ${KEYSTORE_FILE} keystore.jks
ENTRYPOINT [ \
    "java", "-Xmx2g","-Xms32m","-XX:+UseConcMarkSweepGC", \
    "-Dspring.main.lazy-initialization=true", \
    "-Dspring.profiles.active=prod", \
    "-Dptai-authorization-server.sign-key-alias=domain.org pt ai ee authorization service (ptai-integration-service.domain.org)", \
    "-Dptai-integration-service.check-cert-alias=domain.org pt ai ee authorization service (ptai-integration-service.domain.org)", \
    "-Dserver.ssl.key-alias=domain.org pt ai ee integration service (ptai-integration-service.domain.org)", \
    "-Dserver.ssl.key-store=file:/keystore.jks", \
    "-Dserver.ssl.trust-store=file:/keystore.jks", \
    "-Dspring.cloud.consul.host=consul", \
    "-jar", \
    "/ptai-integration-service-0.1-spring-boot.jar","10"]