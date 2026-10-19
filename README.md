# AuthRail Go SDK

## Discover a deployment

An AI Inventory manager first creates a short-lived setup key for an integration
key, AI system name, and deployment name on the AI Inventory page. Keep the key
in the protected application, not in the agent. The integration key is a lookup
name, never authentication. An existing AI Inventory item can be linked from
its detail page instead of creating a second discovered item. Discover once
during setup:

```go
found, err := authrail.Discover(ctx, authrail.DiscoveryConfig{
    ControlPlaneURL: "https://authrail.example.com",
    SetupKey: os.Getenv("AUTHRAIL_SETUP_KEY"),
    AgentKey: "support-assistant",
})
if err != nil { return err }
```

The result has the AI Inventory item, revision, and deployment IDs plus its
confirmation status. Repeating discovery is safe, but an expired or revoked
key fails. Review and confirm the discovered AI system in AuthRail. Discovery
does not issue a deployment credential or allow an action; a tenant manager
sets up the separate sidecar credential and application signing key before
Observe reports. Keep the setup key out of sidecar configuration and never
give it to the agent.

Add AuthRail checks at the Go function that performs an AI-requested action.
Your application still runs the function. The SDK asks the nearby AuthRail
sidecar what the selected Rails would decide about the call and its result.

## Observe an action

Generate a key pair in the protected application's environment, then register
`executor-public.pem` on the deployment page:

```bash
openssl genpkey -algorithm Ed25519 -out executor-private.pem
openssl pkey -in executor-private.pem -pubout -out executor-public.pem
```

Store the private key with your other application secrets and give only the
public key to the sidecar and AuthRail. Load the private key before creating the
client:

```go
privateKeyPEM, err := os.ReadFile(os.Getenv("AUTHRAIL_EXECUTOR_PRIVATE_KEY_FILE"))
if err != nil { return err }
executorPrivateKey, err := authrail.ParseExecutorPrivateKeyPEM(privateKeyPEM)
if err != nil { return err }
```

Set up the client once in the protected application, then wrap the function you
already use:

```go
client, err := authrail.NewClient(authrail.Config{
    SidecarURL:   "http://127.0.0.1:7078",
    AdapterToken: os.Getenv("AUTHRAIL_ADAPTER_TOKEN"),
    OrganisationID: organisationID,
    DeploymentID: deploymentID,
    ExecutorPrivateKey: executorPrivateKey,
})
if err != nil { return err }

receipt, checks, err := authrail.Observe(ctx, client, authrail.Operation{
    VersionID: refundOperationVersionID,
    ActionKey: refund.ID,
    PrincipalID: currentStaff.ID,
    PrincipalSource: "application_session",
    SessionID: task.ID,
    ResourceID: refund.InvoiceID,
    ResourceSource: "application_lookup",
}, refund, func(ctx context.Context) (Receipt, error) {
    return payments.Refund(ctx, refund)
})
```

`receipt` and `err` are the function's own result and error. The function runs
once even if a Rail would deny it or the sidecar is unavailable. Read
`<-checks` when you want the call and result decisions or an observation error;
that check finishes separately and does not hold up the function's result.

The Operation Version comes from the reviewed action in AuthRail. Give each
business action a stable `ActionKey` and reuse it on a retry. The SDK creates
the request ID and JSON for you. Supply opaque principal and task/session IDs;
use an opaque resource ID when the action targets one. AuthRail records these
as references supplied by your application, without independently verifying
the person or resource in Observe mode. `ExecutorPrivateKey` is an Ed25519
private key held by your protected application. Give its PEM public key to the
sidecar through `AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE`. The SDK signs each call and
result check for 30 seconds; the sidecar rejects a changed, expired, or missing
signature. Derive principal and resource IDs from your application's trusted
session and resource lookup before calling `Observe`. Set `PrincipalSource` to
`application_session` or `service_identity` based on that authentication. For an
Operation with a resource identity field, use the exact ID in the reviewed
argument and set `ResourceSource` to `application_lookup`. Otherwise leave
`ResourceID` empty and set `ResourceSource` to `not_applicable`. Missing or
mismatched claims make the local check unavailable, not an allow. These are
signed application claims, not independent AuthRail verification of a person
or record. Keep the signing key and
adapter token with the protected
application, away from the agent. The sidecar uses its own separate deployment
credential to fetch Rails and report covered decisions to AuthRail. A decision's
`RecordingStatus` is `retained`, `queued`, or `unavailable`. A queued report is
saved by the sidecar for retry, but has no certificate yet. A retained response
includes its Action and certificate IDs.

Register the matching application public key on the deployment page before
sending signed reports. AuthRail verifies the signature against that registered
key when retaining a report, including one retried from the sidecar queue. A
signed assertion proves that the application key supplied the references; your
application still authenticates the person and resolves the resource.

## Read a live fact in your protected application

`LookupStripeInvoiceStatus` supports a normal Stripe account by default. It
first reads Stripe's current account with the application's credential and
requires its ID to match the reviewed account, then reads the invoice. Set
`ConnectedAccount: true` only for Stripe Connect: the invoice request then
sends the reviewed connected account ID in `Stripe-Account`. Both paths reject
redirects and a returned invoice with a different ID, and return `unavailable`
on timeout or provider failure. A mismatched account is `untrusted`. Never
give the Stripe credential to the agent.

`LookupCustomerFact` calls your named, read-only lookup with a bounded context.
Your callback must honor cancellation, keep its database or API credential in
the protected application, return the exact source, lookup, and account or
tenant it read, and return the source observation time. The helper rejects a
different source or account;
it does not turn a cached result into a fresh one. Both helpers return the
source version, lookup key, account, observation time, and bounded value for
the local decision protocol. Configure them from the **exact reviewed Context
Source Version**, not a copied endpoint or an agent-provided account ID.

For example, read a Stripe invoice before the protected action and attach the
resolution to that action's `Operation`:

```go
fact, err := authrail.LookupStripeInvoiceStatus(ctx, authrail.StripeInvoiceSource{
    SourceVersionID: reviewedSourceVersionID,
    ProviderAccountID: reviewedStripeAccountID,
    Timeout: time.Duration(reviewedTimeoutMs) * time.Millisecond,
    SecretKey: stripeSecretHeldByApplication,
}, refund.InvoiceID)
if err != nil { return err }
operation.FactResolutions = []authrail.FactResolution{fact}
```

The action arguments must contain the invoice ID in the exact field reviewed
for that source. A provider outage returns an `unavailable` fact, not a guessed
status. A configuration error is returned separately and must be handled by the
protected application.

For a customer API, `NewCustomerAPIReader` supplies a concrete HTTPS read-only
callback. Configure its fixed collection endpoint and bearer credential in the
protected application. It performs one `GET` for the record key, does not follow
redirects, and accepts only a bounded JSON response shaped as
`{"accountId":"tenant_123","recordId":"invoice_123","observedAt":"...","data":{...}}`.
`LookupCustomerFact` compares the returned account, record key, source name,
and lookup with the reviewed source before the sidecar checks the projected
fact and its freshness. Other customer-owned sources can implement the same
`CustomerRead` callback contract without placing credentials in AuthRail.

Pass the returned resolution in `Operation.FactResolutions` when calling
`Observe`. The SDK signs it together with the action input. The sidecar checks
the exact published Data Rail's source version, account, lookup, record key,
value type, and freshness before a Policy Rail may read the fact. Missing,
stale, mismatched, and unavailable facts cannot satisfy the rule. AuthRail
retains only the reported fact status and source/lookup provenance in the
Observe certificate, not the fact value or record key. A successful read is
context, not authorization of the requested business action, and Observe still
does not stop the action.

**Current scope:** Observe checks Go structs or maps sent to a sidecar on the
same host. Decisions are advisory. This version does not stop actions or handle
approvals. AuthRail retains covered reports when reachable; a missing report
remains visible as a recording gap.
