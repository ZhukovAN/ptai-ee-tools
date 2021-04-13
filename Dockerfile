FROM maven:3.6.3-jdk-8 AS builder

ENV BUILD_HOME=/ptai-ee-tools

RUN mkdir -p $BUILD_HOME

COPY pom.xml $BUILD_HOME
COPY ptai-i18n/src $BUILD_HOME/ptai-i18n/src
COPY ptai-i18n/pom.xml $BUILD_HOME/ptai-i18n/
COPY ptai-data-structures/src $BUILD_HOME/ptai-data-structures/src
COPY ptai-data-structures/pom.xml $BUILD_HOME/ptai-data-structures/
COPY ptai-rest-api/src $BUILD_HOME/ptai-rest-api/src
COPY ptai-rest-api/pom.xml $BUILD_HOME/ptai-rest-api/
COPY generic-client-lib/src $BUILD_HOME/generic-client-lib/src
COPY generic-client-lib/pom.xml $BUILD_HOME/generic-client-lib/
COPY ptai-cli-plugin/src $BUILD_HOME/ptai-cli-plugin/src
COPY ptai-cli-plugin/pom.xml $BUILD_HOME/ptai-cli-plugin/
COPY ptai-jenkins-plugin/src $BUILD_HOME/ptai-jenkins-plugin/src
COPY ptai-jenkins-plugin/pom.xml $BUILD_HOME/ptai-jenkins-plugin/
COPY ptai-teamcity-plugin/build $BUILD_HOME/ptai-teamcity-plugin/build
COPY ptai-teamcity-plugin/ptai-teamcity-plugin-agent $BUILD_HOME/ptai-teamcity-plugin/ptai-teamcity-plugin-agent
COPY ptai-teamcity-plugin/ptai-teamcity-plugin-common $BUILD_HOME/ptai-teamcity-plugin/ptai-teamcity-plugin-common
COPY ptai-teamcity-plugin/ptai-teamcity-plugin-server $BUILD_HOME/ptai-teamcity-plugin/ptai-teamcity-plugin-server
COPY ptai-teamcity-plugin/*.xml $BUILD_HOME/ptai-teamcity-plugin/

WORKDIR $BUILD_HOME
RUN mvn clean install -DskipTests=true

FROM openjdk:8-jre

WORKDIR /opt/ptai/bin
COPY --from=builder /ptai-ee-tools/ptai-cli-plugin/target/ptai-cli-plugin.jar .

# Create generic entrypoint that simply executes command passed to docker container
# and shell wrapper around PTAI CLI JAR file to not to bother user with that file location
RUN echo '#!/bin/sh' > /usr/local/bin/entrypoint.sh && \
    echo >> /usr/local/bin/entrypoint.sh && \
    echo 'exec "$@"' >> /usr/local/bin/entrypoint.sh && \
    echo '#!/bin/sh' > /opt/ptai/ptai-cli-plugin && \
    echo >> /opt/ptai/ptai-cli-plugin && \
    echo "java -jar /opt/ptai/bin/ptai-cli-plugin.jar " '"$@"' >> /opt/ptai/ptai-cli-plugin && \
    chmod +x /usr/local/bin/entrypoint.sh && \
    chmod +x /opt/ptai/ptai-cli-plugin && \
    ln -s /opt/ptai/ptai-cli-plugin /usr/bin/ptai-cli-plugin


ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Print PTAI CLI plugin help if image started without parameters
CMD ["ptai-cli-plugin", "--help"]
