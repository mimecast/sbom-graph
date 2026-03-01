# Contracts

This project is a library for processing CycloneDX SBOM files into a model that can then be persisted to a FalkorDB graph database.

## Security Requirements

- Connections to the FalkorDB must only happen over TLS
- Connections to the FalkorDB must be Authenticated
