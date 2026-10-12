# Public test credentials

These private keys and certificates are intentionally public, non-production fixtures for real mTLS protocol tests. The server SAN binds the fixed test NodeUID. Separate CAs isolate controller client authentication from host server authentication. Never install these in a deployment. The CA private keys are discarded after generation.

The `second-server` certificate and separate server CA bind NodeUID `20000000-0000-4000-8000-000000000002`. This identity lets the normal enrollment test reach the duplicate-name inventory guard with a different NodeUID, boot ID and cloud instance. Its client authentication still uses the original client CA. The production client's hostname and certificate validation remain enabled.
