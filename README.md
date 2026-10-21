<p align="center">
  <img src="assets/authrail-logo.png" alt="AuthRail" width="120" />
</p>

# AuthRail Go SDK

The AuthRail Go SDK is an adapter for checking AI-requested actions in a
protected Go application. Put its checks at the function that handles each
action. Your application keeps the tool, provider credentials, and business
workflow. The SDK asks a sidecar on the same host what the active Rails would
decide, then returns the function's own result separately from the check.

**Observe checks are advisory.** A would-deny decision, missing sidecar, or
recording failure does not stop the function. A decision is not proof of
execution or universal interception.

`Observe` remains advisory even when a deployment is switched to Enforce.
Use `Enforce` at a protected function that owns provider credentials and has
been reviewed for bypass paths. It stops before the effect unless the call is
fresh, allowed, and centrally retained. It sends authenticated start and
completion receipts, then checks the result before exposing it. A result
block cannot undo an effect already completed.

## Install and prepare

Go 1.26 or newer is required.

```bash
go get github.com/AuthRail/authrail-sdk-go
```

Before adding a check:

1. Review the action and its exact Operation Version in AuthRail.
2. Register an Observe deployment and start its customer-side sidecar with a
   deployment credential, private durable state, and separate adapter token.
   Follow the [sidecar setup guide](https://github.com/AuthRail/authrail-sidecar#readme);
   the SDK cannot evaluate Rails or deliver reports without it.
3. Register the protected application's Ed25519 public key on that deployment.
   Keep the private key and provider credentials outside the agent.
4. Derive the principal, session, and optional resource ID from your
   application's authenticated context, not from model text.

Start with [Observe an action](#observe-an-action). Use
[Discover a deployment](#discover-a-deployment) only when onboarding an AI
system through a tenant-issued setup key. The later sections show how to add
trusted session history, live source reads, and bounded AI-assisted facts.
For a Node.js application, use the
[Node SDK](https://github.com/AuthRail/authrail-sdk-node) with the same sidecar.

## Enforce a protected action

Use a stable business `ActionKey` across process restarts. The callback must
use the supplied `ProviderIdempotencyKey` at the provider and retain the
`ExecutionContext` so it can query the provider after a timeout. An AuthRail
Action key alone does not deduplicate a provider effect.

```go
receipt, callDecision, resultDecision, err := authrail.Enforce(ctx, client,
    authrail.Operation{
        VersionID: paymentOperationVersionID,
        ActionKey: invoice.PaymentActionKey,
        PrincipalID: authenticatedStaff.ID,
        SessionID: task.ID,
        ResourceID: invoice.ID,
        PrincipalSource: "application_session",
        ResourceSource: "application_lookup",
    }, paymentRequest, func(ctx context.Context, checked PaymentRequest,
        execution authrail.ExecutionContext) (PaymentReceipt, error) {
        return payments.Pay(ctx, checked, execution.ProviderIdempotencyKey)
    })
```

`callDecision` is permission, not execution proof. A successful return means
the protected callback returned, AuthRail retained its signed success receipt,
and the result check allowed exposure. The receipt remains an authenticated
executor assertion, not independent provider proof.
The [executable HTTP handler example](examples/enforce-payment/main.go) uses a
mock provider ledger and one fixed test action key. Replace that key with a
distinct stable business key for each real effect, and derive the caller from
your authenticated application context.

On `ApprovalRequired`,
save the pending value while this process waits for a named human decision,
then call `ResumeApproval` with the same protected operation. A process restart
does not restore the in-memory pending callback. An uncertain claim must be
reviewed before any new claim or effect.

On `OutcomeUnknownError`, inspect its `Recovery` value and query the provider
with the original idempotency key. Call `client.Reconcile` only after that
lookup establishes success or no effect. Unknown is not failure and never
permits a blind retry. A fresh attempt requires a new signed call decision and
any newly required approval. The result hook reports a separate exposure
decision; it cannot roll back a provider operation.

For request correlation, set `Operation.Traceparent` from the protected
application's validated W3C trace context. It is telemetry only, not an
identity or authorization claim.

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

## Supply prior session reads

For a Guard rule that checks an earlier read, the protected application may
attach a `TrajectorySnapshot` to the Operation. Use the authenticated task's
`SessionID`, and include only exact Operation Version IDs whose **result hook
completed successfully** earlier in that task. Set `Complete: true` only when
the application can account for the full relevant history; otherwise omit the
snapshot or leave it incomplete. On the first checked call for a new task,
set `Start: true` with a complete empty list. Its result hook carries the same
start snapshot. Keep the same session ID on subsequent actions, with
`Start: false` and the full ordered list of unique earlier covered read
Operation Versions. The source read Operation must have call and
result coverage in the active signed bundle. Never build this list from
agent-supplied text.

```go
operation.Trajectory = &authrail.TrajectorySnapshot{
    SessionID: operation.SessionID,
    Start: true,
    Complete: true,
    PriorReadOperationVersionIDs: []string{},
}
```

The SDK signs this bounded snapshot with each hook and sends the result check
after the call check completes, without delaying the tool function. The sidecar
keeps a private, bounded history of matching signed call and successful result
hooks and checks exact ordered versions for the same principal and session.
A missing, changed, incomplete, or unrecoverable history leaves the local check
unavailable, not allowed. The application assertion is still not independent
proof that every earlier read was intercepted: a bypassed hook is invisible.
The SDK freezes the supplied context before asynchronous checks so later
application mutations cannot change what was signed. `Values` may also
carry small, typed session fields already reviewed
on the exact Operation; unreviewed or wrongly typed fields are rejected. Do
not put arbitrary conversation text or model output in `Values`. Do not use
session fields to claim a prior business effect: a successful tool result
check is not an authenticated execution receipt. Raw session
history and values are not sent to AuthRail.

## Read a live fact in your protected application

`LookupStripeInvoiceStatus` supports a normal Stripe account by default. It
first reads Stripe's current account with the application's credential and
requires its ID to match the reviewed account, then reads the invoice. Set
`ConnectedAccount: true` only for Stripe Connect: the account and invoice
requests then send the reviewed connected account ID in `Stripe-Account`. Both paths reject
redirects and a returned invoice with a different ID, and return `unavailable`
on timeout or provider failure. A mismatched account is `untrusted`. Never
give the Stripe credential to the agent.

`LookupQuickBooksInvoiceBalance` reads one invoice from the reviewed
QuickBooks Online realm with an application-owned OAuth access token. Set
`Sandbox: true` only for an Intuit test company; otherwise it uses the fixed
production host. The bounded result has `Invoice.Balance`, matching the
reviewed Data Rail. A different invoice ID or invalid balance is `untrusted`;
provider failure or a redirect is `unavailable`. Supply the exact realm,
invoice ID, timeout, and Context Source Version from the reviewed contract,
never from the agent. The application owns token acquisition and refresh; the
SDK does not store a refresh token or create a QuickBooks connection.
`Balance` is in the invoice's currency; this source contract does not pin a
currency, so a numeric threshold must not be presented as currency-qualified
without another reviewed source.

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

## Read a bounded AI-assisted fact

Review an **AI-assisted reading** information source in AuthRail first. Pin its
document source and account, one typed result field, exact model and settings
fingerprint, reading-instructions version, size limits, freshness, and timeout.
In the protected application, call `ExtractContextFact` with that exact source
version, authenticated document bytes, an opaque source location, observation
time, and a callback that invokes your configured model. The callback must
honor its context deadline and return a single JSON primitive of the reviewed
type. It must report the model, settings, and instructions actually used, plus
whether the reading is uncertain. Keep model credentials and raw documents out
of the agent and sidecar.

The helper hashes the bounded document, checks the callback's version claims,
type and output size, and constructs the reviewed result field. It returns an
`unavailable` resolution on timeout, `uncertain` when the callback cannot make
a reliable assertion, or `untrusted` for mismatched or malformed output. Pass
that resolution in `Operation.FactResolutions`; the signed sidecar protocol
checks it again against the published source. The model never returns an
authorization decision. AuthRail records bounded provenance and status, not
the document or extracted value. A matching model claim is not independent
proof that the model read the document or interpreted it correctly.

For the reviewed OpenAI Decisions source, use `gpt-6-luna` and one predicate,
choice, or score question. Pin `OpenAIDecisionsConfigSHA256(question)` as the
Context Source Version's settings fingerprint before publishing it. The
protected application supplies the OpenAI key and document bytes; neither
goes to the agent, sidecar, or AuthRail server:

```go
question := authrail.DecisionsQuestion{
    Type: "predicate",
    Instructions: "Does this message contain a payment card number?",
    MinConfidence: 0.8,
}
digest, err := authrail.OpenAIDecisionsConfigSHA256(question)
if err != nil { return err }
if digest != reviewedSource.ModelConfigSHA256 { return errors.New("reviewed contextual question changed") }
extractor, err := authrail.NewOpenAIDecisionsExtractor(authrail.OpenAIDecisionsConfig{
    Source: reviewedSource,
    Question: question,
    APIKey: openAIKeyHeldByApplication,
})
if err != nil { return err }
fact, err := authrail.ExtractContextFact(ctx, reviewedSource, message.ID,
    message.SourceLocation, message.ObservedAt, message.Bytes, extractor)
if err != nil { return err }
operation.FactResolutions = []authrail.FactResolution{fact}
```

The Decisions API receives only bounded document text from this protected
application. A refusal or a predicate probability between the reviewed true
and false thresholds returns `uncertain`; a sufficiently low probability
returns `false`. Choice and score answers below the confidence threshold are
also `uncertain`. Timeout or provider failure returns `unavailable`.
Neither supplies a trusted fact. A confident answer remains contextual input
to the published Rail, never a final allow decision or independent proof that
the model understood the document.
