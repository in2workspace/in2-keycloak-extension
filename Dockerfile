# Primera etapa: Compilación de la aplicación
FROM maven:3.8.4-openjdk-17-slim AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
COPY /api/api.yaml ./api/
COPY /api/openapi.yaml ./api/
RUN mvn clean install

# Segunda etapa: Creación de la imagen de Keycloak
FROM quay.io/keycloak/keycloak:24.0.1
USER root
RUN ["sed", "-i", "s/SHA1, //g", "/usr/share/crypto-policies/DEFAULT/java.txt"]
USER 1000

# Copiar el artefacto de la aplicación desde la etapa de compilación
COPY --from=builder /app/target/classes/keyfile.json /opt/keycloak/providers/keyfile.json
COPY --from=builder /app/target/in2-keycloak-extension-1.1.1.jar /opt/keycloak/providers/

#ENV KC_SPI_THEME_ADMIN_DEFAULT=siop-2
ENV VCISSUER_ISSUER_DID="did:key:z6MkqmaCT2JqdUtLeKah7tEVfNXtDXtQyj4yxEgV11Y5CqUa"
ENV VCISSUER_ISSUER_KEY_FILE="/opt/keycloak/providers/keyfile.json"

#RUN bash -c 'touch /app/in2-issuer-backend-0.2.0-SNAPSHOT.jar'
#COPY azure/applicationinsights-agent-3.4.8.jar  /build/applicationinsights-agent-3.4.8.jar
#COPY azure/applicationinsights.json /build/applicationinsights.json

EXPOSE 8080
ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start-dev", "--health-enabled=true","--metrics-enabled=true", "--log-level=INFO", "--import-realm"]