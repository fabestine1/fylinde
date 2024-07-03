# Stage 1: Base build
FROM ubuntu:latest as base

# Install curl, unzip, and OpenJDK for Keycloak
RUN apt-get update && \
    apt-get install -y curl unzip openjdk-11-jdk && \
    apt-get clean

# Stage 2: Build Keycloak
FROM base as builder

# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Configure a database vendor
ENV KC_DB=postgres

WORKDIR /opt/keycloak

# Create the conf directory
RUN mkdir -p conf

# Generate a self-signed certificate for demonstration purposes
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 \
    -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore

# Download and unzip Keycloak
RUN curl -LO https://github.com/keycloak/keycloak/releases/download/19.0.1/keycloak-19.0.1.zip && \
    unzip keycloak-19.0.1.zip && \
    ls -la && \
    ls -la keycloak-19.0.1 && \
    mv keycloak-19.0.1/* /opt/keycloak/ || echo "Directory not found!" && \
    rm -rf keycloak-19.0.1 keycloak-19.0.1.zip

RUN /opt/keycloak/bin/kc.sh build

# Stage 3: Final stage
FROM ubuntu:latest as final

# Install Java for Keycloak
RUN apt-get update && \
    apt-get install -y openjdk-11-jdk && \
    apt-get clean

# Copy the built Keycloak server from the builder stage
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# Set environment variables for the PostgreSQL database
ENV KC_DB=postgres
ENV KC_DB_URL=jdbc:postgresql://postgres_keycloak_demo:5433/keycloak
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=password
ENV KC_HOSTNAME=localhost
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
ENV OIDC_CLIENT_ID=auth-service
ENV OIDC_CLIENT_SECRET=CfHbE6DxCEGbv0ou6GR0fPgaRyZC6Bju
ENV OIDC_DISCOVERY_URL=http://keycloak:8080/realms/fylinde_ecommerce/.well-known/openid-configuration

# Copy the custom configuration files
COPY cache-ispn-jdbc-ping.xml /opt/keycloak/conf/
COPY keycloak.keystore /opt/keycloak/conf/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start"]
