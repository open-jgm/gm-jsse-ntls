# Test TLS materials

Files under `client/` and `server/` are **synthetic SM2 test credentials** for local development and CI only.

- PKCS#12 passwords in tests use `12345678` (see `GmsslTestMaterialPaths.DEFAULT_PWD`).
- **Do not** use these certificates or keys in production.
- Paths are resolved by `GmsslTestMaterialPaths` from classpath, `src/test/resources`, or `target/test-classes`.