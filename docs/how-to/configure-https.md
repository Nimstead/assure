# Configure HTTPS

Use this guide before you connect browsers or agents from another machine. You need an Assure server and control of its hostname and reverse proxy.

Agents refuse plain HTTP except for local testing, so anything beyond one machine needs TLS. Any reverse proxy works. With [Caddy](https://caddyserver.com), which gets a certificate for you:

```
assure.example.com {
	reverse_proxy localhost:8000
}
```

Then set in `.env`:

```
NIMSTEAD_PUBLIC_URL=https://assure.example.com
FORWARDED_ALLOW_IPS=<your proxy's address as the app container sees it>
```

and run `docker compose up -d` again.

The first account you create sets the server up and is its admin. Later sign-ups create another organisation through an emailed link. Configure [SMTP](../configuration.md#alerts) if you need these sign-ups. Colleagues in your organisation join through single sign-on.

## Verify the connection

Open the configured HTTPS URL and sign in. Confirm that your browser trusts the certificate. Check that the enrolment command in Assure uses the same HTTPS origin.

If sign-in returns to the login screen, check the cookie's secure connection and the proxy's forwarded headers. Do not disable secure cookies for a production deployment.
