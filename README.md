<div align="center">

<h1>IN2 Keycloak Extension</h1>
<span>by </span><a href="https://in2.es">in2.es</a>
<p><p>

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-keycloak-extension&metric=alert_status)](https://sonarcloud.io/dashboard?id=in2workspace_in2-keycloak-extension)

[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=bugs)](https://sonarcloud.io/summary/new_code?in2workspace_credential-issuer)
[![Vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=in2workspace_credential-issuer)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=security_rating)](https://sonarcloud.io/dashboard?id=in2workspace_credential-issuer)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=code_smells)](https://sonarcloud.io/summary/new_code?id=in2workspace_credential-issuer)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=ncloc)](https://sonarcloud.io/dashboard?id=in2workspace_credential-issuer)

[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_in2-keycloak-extension&metric=coverage)](https://sonarcloud.io/summary/new_code?id=in2workspace_in2-keycloak-extension)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=duplicated_lines_density)](https://sonarcloud.io/summary/new_code?id=in2workspace_credential-issuer)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=in2workspace_credential-issuer)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=in2workspace_credential-issuer)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=in2workspace_credential-issuer&metric=sqale_index)](https://sonarcloud.io/summary/new_code?id=in2workspace_credential-issuer)

</div>

# Introduction

The Keycloak Extension is a service that allows to build the identity provider solution for the Issuer application. 
It composes of an official Keycloak image and integrates a custom layer with tailored logic 
to comply with the requirement of the technical specification [OpenID4VCI DOME profile](https://dome-marketplace.github.io/OpenID4VCI-DOMEprofile/openid-4-verifiable-credential-issuance-wg-draft.html)
(Issuer-initiated flow)

# Installation

As a key part of the Credential Issuer solution, the Keycloak extension is designed to work with the following dependencies:

## Dependencies

To use the Credential Issuer, you will need the following components:

- **Issuer-UI**
- **Issuer-API**
- **Issuer Keycloak Plugin**
- **Postgres Database**
- **SMTP Email Server**

For each dependency, you can refer to their respective repositories for detailed setup instructions.
We offer a Docker image to run the application. You can find it in [Docker Hub](https://hub.docker.com/u/in2workspace).

Here, you can find an example of how to run the application with all the required services and configuration.

### Issuer UI
Issuer UI is the user interface for the Credential Issuer. Refer to the [Issuer UI Documentation](https://github.com/in2workspace/issuer-ui) for more information on configuration variables.

### Issuer API
The Server application of the Credential Issuer. Refer to the [Issuer API Documentation](https://github.com/in2workspace/issuer-api) for more information on configuration variables.

### Issuer Keycloak Plugin
The application needs key custom environment variables to be configured
- ISSUER_API_URL: internal Issuer API url
- ISSUER_API_EXTERNAL_URL external Issuer API url
- PRE_AUTH_LIFESPAN: expiration of the pre-authorized code (Credential Offer)
- PRE_AUTH_LIFESPAN_TIME_UNIT: unit of the expiration of the pre-authorized code
- TX_CODE_SIZE: size of the PIN code
- TX_CODE_DESCRIPTION: description message for the PIN entry
- TOKEN_EXPIRATION: expiration of the deferred flow in seconds
#### Example of a typical configuration:
```
docker run -d \
  --name issuer-keycloak \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e KC_HOSTNAME_URL=https://localhost:8443 \
  -e KC_HOSTNAME_ADMIN_URL=https://localhost:8443 \
  -e KC_HTTPS_CLIENT_AUTH=request \
  -e KC_DB=postgres \
  -e KC_DB_USERNAME=postgres \
  -e KC_DB_PASSWORD=postgres \
  -e KC_DB_URL=jdbc:postgresql://issuer-keycloak-postgres/cred \
  -e ISSUER_API_URL=http://issuer-api:8080 \
  -e ISSUER_API_EXTERNAL_URL=http://issuer-api-external.com \
  -e PRE_AUTH_LIFESPAN=10 \
  -e PRE_AUTH_LIFESPAN_TIME_UNIT=MINUTES \
  -e TX_CODE_SIZE=4 \
  -e TX_CODE_DESCRIPTION="Enter the PIN code" \
  -e TOKEN_EXPIRATION=2592000 \
  -p 7001:8080 \
  -p 8443:8443 \
  in2workspace/issuer-keycloak-plugin:v1.1.0
```
You can find more information in the official [Keycloak documentation](https://www.keycloak.org/documentation)

### Postgres Database
Postgres is used as the database for Keycloak.
You can find more information in the [official documentation](https://www.postgresql.org/docs/).
#### Example of a typical configuration:
```bash
docker run -d \
  --name issuer-keycloak-postgres \
  -e POSTGRES_DB=cred \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 5433:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  postgres:16.3
```
Ensure you have the volume postgres_data created before running the postgres container:
```bash
docker volume create postgres_data
```

### SMTP Email Server
An SMTP Email Server of your choice. It must support StartTLS for a secure connection. Refer to the [Issuer API Documentation](https://github.com/in2workspace/issuer-api) for more information

## Contribution

### How to contribute
If you want to contribute to this project, please read the [CONTRIBUTING.md](CONTRIBUTING.md) file.

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Project/Component Status
This project is currently in development.

## Contact
For any inquiries or further information, feel free to reach out to us:

- **Email:** [In2 Dome Support](mailto:domesupport@in2.es)
- **Name:** IN2, Ingeniería de la Información
- **Website:** [https://in2.es](https://in2.es)

## Acknowledgments
This project is part of the IN2 strategic R&D, which has received funding from the [DOME](https://dome-marketplace.eu/) project within the European Union’s Horizon Europe Research and Innovation programme under the Grant Agreement No 101084071.
