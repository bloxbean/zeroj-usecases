# Runtime base image: Amazon Corretto 25 LTS (OpenJDK, GPLv2 + Classpath Exception) on Amazon Linux 2023.
# 25.0.5.1 fixes CVE-2026-114938 ("Java4Shell"); Temurin has no fixed 25 build yet.
# Pinned by multi-arch index digest (linux/amd64 + linux/arm64). Override with --build-arg BASE_IMAGE=...
ARG BASE_IMAGE=amazoncorretto:25.0.5-al2023-headless@sha256:d43cc2b87faf3e80d04659d315dd9f1dba2c1176cc9b48d9daed285856ac056c

FROM eclipse-temurin:25-jdk AS build

ARG USECASE_DIR
# Empty = use zerojVersion from version.properties (copied below); set to override.
ARG ZEROJ_VERSION=
ARG PUBLISH_LOCAL_ZEROJ=false
ARG ZEROJ_PUBLISH_TASKS=":zeroj-api:publishToMavenLocal :zeroj-backend-spi:publishToMavenLocal :zeroj-codec:publishToMavenLocal :zeroj-bls12381:publishToMavenLocal :zeroj-blst:publishToMavenLocal :zeroj-crypto:publishToMavenLocal :zeroj-circuit-dsl:publishToMavenLocal :zeroj-circuit-annotation-api:publishToMavenLocal :zeroj-circuit-annotation-processor:publishToMavenLocal :zeroj-circuit-lib:publishToMavenLocal :zeroj-verifier-groth16:publishToMavenLocal :zeroj-onchain-julc:publishToMavenLocal"

WORKDIR /workspace/zeroj
COPY --from=zeroj-src . ./

RUN if [ "${PUBLISH_LOCAL_ZEROJ}" = "true" ]; then \
      chmod +x ./gradlew \
      && ./gradlew --no-daemon ${ZEROJ_PUBLISH_TASKS} -x test -PskipSigning; \
    fi

WORKDIR /workspace/usecase
COPY version.properties /workspace/version.properties
COPY gradle/usecase-versions.gradle /workspace/gradle/usecase-versions.gradle
COPY ${USECASE_DIR}/ ./

RUN chmod +x ./gradlew \
    && ./gradlew --no-daemon bootJar -x test ${ZEROJ_VERSION:+-PzerojVersion=${ZEROJ_VERSION}} \
    && jar_file="$(find build/libs -maxdepth 1 -type f -name '*.jar' ! -name '*-plain.jar' | head -n 1)" \
    && test -n "${jar_file}" \
    && cp "${jar_file}" /workspace/app.jar

FROM ${BASE_IMAGE}

ARG USECASE_DIR

ENV WAIT_FOR_PROVIDER=true
ENV SERVER_PORT=8080
ENV BLOCKFROST_BASE_URL=http://host.docker.internal:8080/api/v1/
ENV BLOCKFROST_PROJECT_ID=
ENV CARDANO_NETWORK=yaci
ENV CARDANO_BLOCKFROST_BASE_URL=http://host.docker.internal:8080/api/v1/
ENV CARDANO_BLOCKFROST_PROJECT_ID=
ENV CARDANO_YACI_BASE_URL=http://host.docker.internal:8080/api/v1/
ENV CARDANO_YACI_ADMIN_URL=http://host.docker.internal:10000
ENV ZEROJ_ALLOW_INSECURE_TRUSTED_SETUP=true

# curl and ca-certificates are in the base image; findutils provides find, which
# docker/run-spring-usecase.sh uses to seed the demo cache.
RUN dnf install -y findutils \
    && dnf clean all \
    && rm -rf /var/cache/dnf

WORKDIR /app
COPY --from=build /workspace/app.jar /app/app.jar
COPY demo-cache/${USECASE_DIR}/ /opt/zeroj-demo-cache/
COPY docker/run-spring-usecase.sh /usr/local/bin/run-spring-usecase
RUN chmod +x /usr/local/bin/run-spring-usecase

ENTRYPOINT ["/usr/local/bin/run-spring-usecase"]
