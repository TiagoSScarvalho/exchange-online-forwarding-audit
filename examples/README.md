# Simulated forwarding finding

These files come from the offline `workedexample` fixture. Every mailbox, domain, tenant identifier and rule value is fictional. They are not a tenant export or evidence of delivered mail.

Download/open [report.html](report.html) locally to inspect the report, or review [forwarding.csv](forwarding.csv) directly.

| Field | Example |
| --- | --- |
| Mailbox | `lab@contoso.com` |
| Rule | `Supplier copy` |
| Action | `ForwardTo` |
| Configured destination | `contact@contoso.com` |
| Resolved next hop | `contact@external.example` |
| Classification | `ExternalDomain` |
| Delivery evidence | `NotTested` |

The report counts one enabled external candidate. An administrator still needs to review the rule conditions, the contact, business approval and applicable mail-flow controls. Use message trace to investigate a particular message. This example does not establish delivery or compromise.
