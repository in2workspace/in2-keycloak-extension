# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/)
and this project adheres to [Semantic Versioning](http://semver.org/).

## [release v1.1.1]
### Changed
- Update some external config variables to be internal and not exposed externally

## [release v1.1.0] 
### Added
- Implementation of tx_code PIN according to DOME profile
- Lifespan of token and PIN by environment variables
- Authorization server metadata endpoint

## [release v1.0.0] - 2024-02-12
### Added
- Added custom providers for the client-registration functionality for SIOP2 clients in Keycloak. Implements methods for creating, updating, and deleting SIOP2 clients.
- Added custom providers functionality for issuing Verifiable Credentials to users based on their roles in registered SIOP-2 clients.