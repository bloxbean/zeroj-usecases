FROM eclipse-temurin:25-jdk AS build

ARG USECASE_DIR
ARG ZEROJ_VERSION=0.1.0-pre7
ARG PUBLISH_LOCAL_ZEROJ=false
ARG ZEROJ_PUBLISH_TASKS=":zeroj-api:publishToMavenLocal :zeroj-backend-spi:publishToMavenLocal :zeroj-codec:publishToMavenLocal :zeroj-bls12381:publishToMavenLocal :zeroj-blst:publishToMavenLocal :zeroj-crypto:publishToMavenLocal :zeroj-circuit-dsl:publishToMavenLocal :zeroj-circuit-annotation-api:publishToMavenLocal :zeroj-circuit-annotation-processor:publishToMavenLocal :zeroj-circuit-lib:publishToMavenLocal :zeroj-verifier-groth16:publishToMavenLocal :zeroj-onchain-julc:publishToMavenLocal"

WORKDIR /workspace/zeroj
COPY --from=zeroj-src . ./

RUN if [ "${PUBLISH_LOCAL_ZEROJ}" = "true" ]; then \
      chmod +x ./gradlew \
      && ./gradlew --no-daemon ${ZEROJ_PUBLISH_TASKS} -x test -PskipSigning; \
    fi

WORKDIR /workspace/usecase
COPY gradle/usecase-versions.gradle /workspace/gradle/usecase-versions.gradle
COPY ${USECASE_DIR}/ ./

RUN chmod +x ./gradlew \
    && ./gradlew --no-daemon bootJar -x test -PzerojVersion=${ZEROJ_VERSION} \
    && jar_file="$(find build/libs -maxdepth 1 -type f -name '*.jar' ! -name '*-plain.jar' | head -n 1)" \
    && test -n "${jar_file}" \
    && cp "${jar_file}" /workspace/app.jar

FROM eclipse-temurin:25-jre

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

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=build /workspace/app.jar /app/app.jar
COPY demo-cache/${USECASE_DIR}/ /opt/zeroj-demo-cache/
COPY docker/run-spring-usecase.sh /usr/local/bin/run-spring-usecase
RUN chmod +x /usr/local/bin/run-spring-usecase

ENTRYPOINT ["/usr/local/bin/run-spring-usecase"]
