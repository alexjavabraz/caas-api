# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest) | Yes |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Send a report to **alexjavabraz@gmail.com** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected versions

### Response timeline

- **Acknowledgement**: within 48 hours
- **Status update**: within 7 days
- **Critical/high severity fix**: within 30 days
- **Medium/low severity fix**: within 90 days

### Private disclosure

For vulnerabilities that require coordinated disclosure, we support [GitHub Private Security Advisories](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/creating-a-repository-security-advisory). You can open a private advisory directly at:

`https://github.com/alexjavabraz/caas-api/security/advisories/new`

## Scope

- Authentication bypass or token forgery
- SQL injection or database exposure
- AMQP/RabbitMQ message injection
- Privilege escalation between developer accounts
- Secrets leaking in logs or API responses

## Out of scope

- Vulnerabilities in third-party dependencies already tracked by `cargo audit`
- Issues that require physical access to the server
- Social engineering attacks
