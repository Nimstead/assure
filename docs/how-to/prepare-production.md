# Prepare a production deployment

Verify operational controls before you use Assure for production hosts. You need an admin account, server access, and an agreed recovery process.

1. [Configure HTTPS](configure-https.md) and set `NIMSTEAD_PUBLIC_URL` and `FORWARDED_ALLOW_IPS` for the proxy.
2. Set a strong `POSTGRES_PASSWORD` before the database's first start.
3. [Back up both volumes](back-up.md) and test recovery on an isolated host.
4. Configure signing-key custody with `NIMSTEAD_VAULT_ADDR` and `NIMSTEAD_VAULT_TOKEN` if you use Vault.
5. Configure `NIMSTEAD_CHECKPOINT_S3` for an object-locked checkpoint bucket if your evidence process requires external checkpoints.
6. Send the evidence key fingerprint from `GET /api/evidence/public-key` to your auditor through a separate trusted channel.
7. [Configure alerts](configure-alerts.md) and verify a test notification at the destination.
8. [Test single sign-on](configure-sso.md) before you enable **Require SSO**.
9. Verify remediation and failure recovery on test machines before you permit production changes.

Keep production remediation disabled until the required controls pass. Review [configuration](../configuration.md), [evidence trust](../explanation/evidence-trust.md), and [remediation safety](../explanation/remediation-safety.md) for their boundaries.
