FROM openjdk:8-jdk-alpine
ARG CLI=target/ptai-cli-plugin-0.1-jar-with-dependencies.jar
ARG TRUSTSTORE=/src/test/resources/keys/truststore.jks
COPY ${CLI} /ptai-cli-plugin.jar
COPY ${TRUSTSTORE} /truststore.jks

RUN echo '#! /bin/sh -eu' > /entrypoint.sh \
  && echo 'exec "$@"' >> /entrypoint.sh \
  && chmod +x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh"]

CMD [ \
    "java", \
    "-jar", \
    "/ptai-cli-plugin.jar"]
