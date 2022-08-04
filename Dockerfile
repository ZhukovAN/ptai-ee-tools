FROM gradle:7.1.1-jdk8 AS builder

COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build --no-daemon

FROM openjdk:8-jre

WORKDIR /opt/ptai/bin
COPY --from=builder /home/gradle/src/ptai-cli-plugin/build/libs/ptai-cli-plugin.jar .
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
