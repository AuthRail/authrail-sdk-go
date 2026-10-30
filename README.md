<p align="center">
  <img src="assets/authrail-logo.png" alt="AuthRail" width="120" />
</p>

# AuthRail Go SDK

AuthRail helps you see what your AI agents are doing and set rules for the
actions they may take. In your AuthRail workspace, you describe an action,
publish its rules, and review the decisions and execution reports it produces.
Those published rules are called **Rails**.

This SDK connects a Go application to AuthRail. Add it around the function
that handles an AI-requested action, such as paying an invoice or posting a
message. Your application keeps its business logic and provider credentials.
The SDK checks the call and its result with an AuthRail **sidecar**: a small
service you run beside the application. The sidecar evaluates the Rails chosen
for that deployment and sends records to your workspace.

Start with **Observe** to see the decisions without changing your application's
behavior. A denied check, unavailable sidecar, or recording failure does not
stop an Observe callback. Use **Enforce** when you are ready to require permission
before the callback and check its result before returning it. A result block
cannot undo an effect already completed. A decision explains permission; an
execution report says what your application reported doing. Neither
independently proves a provider effect.

## Install and prepare

Prepare the AuthRail workspace before running an SDK check:

1. Create an AuthRail account if you need one, then sign in and open your
   organisation's workspace. You need access to manage its AI Inventory and
   Runtime configuration; installing the SDK does not create this setup.
2. Add or select the AI system in **AI Inventory** and confirm its identity.
   Create and review the action it will request, including its input and
   result fields. Keep that action's exact **Operation Version ID** for code.
3. Publish the Rails for that action, then create an **Observe deployment**
   using the reviewed AI system revision and exact Rail versions. A deployment
   identifies the application setup whose decisions you want to track.
4. Generate an Ed25519 application key pair using the commands under
   [Observe an action](#observe-an-action). Register its public key on the
   deployment; keep its private key in the protected application.
5. Start the [AuthRail sidecar](https://github.com/AuthRail/authrail-sidecar#readme)
   for that deployment. Docker is the recommended setup. Configure its
   deployment credential, executor public key, separate adapter token and
   private durable storage, then check its health.
6. Derive the principal, session and optional resource ID from authenticated
   application context, rather than model text.

The SDK runs inside your Go program; the sidecar is a separate process.
Building the SDK or your program does not start the sidecar. The local URL
`http://127.0.0.1:7078` requires the application and sidecar to share a network
namespace. With Docker, follow the sidecar guide for that arrangement; an
unrelated container cannot reach the sidecar through its own loopback address. The **adapter
token** lets the SDK call the sidecar locally; the **deployment credential**
lets the sidecar connect to AuthRail. Keep these credentials, the application's
private signing key and provider credentials outside the agent.

Use Go 1.26 or newer. In your application's module directory, install the
[versioned module](https://pkg.go.dev/github.com/AuthRail/authrail-sdk-go):

```bash
go get github.com/AuthRail/authrail-sdk-go@v0.1.1
```

If you are starting a new application, first create its directory and run
`go mod init` with your application's module path. `go get` records the SDK in
`go.mod` and `go.sum`; it does not start a service. The
[v0.1.1 source tag](https://github.com/AuthRail/authrail-sdk-go/tree/v0.1.1)
identifies this version.

<details>
<summary>Build from source when contributing</summary>

```bash
git clone https://github.com/AuthRail/authrail-sdk-go.git
cd authrail-sdk-go
go build ./...
```

</details>

A successful build exits without starting a server. Start with
[Observe an action](#observe-an-action) in your own program; its code examples
use your existing business types and authenticated application context.
[Discover a deployment](#discover-a-deployment) is an optional onboarding path
through a short-lived setup key, rather than a substitute for the reviewed
configuration above. For Node.js, use the
[Node SDK](https://github.com/AuthRail/authrail-sdk-node) with the same sidecar.

## Observe an action

Generate a key pair in the protected application's environment, then register
`executor-public.pem` on the deployment page:

```bash
umask 077
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

For example, after handling the function's own error, inspect the checks:

```go
observation := <-checks
if observation.CallError != nil || observation.ResultError != nil {
    log.Printf("AuthRail check unavailable: call=%v result=%v",
        observation.CallError, observation.ResultError)
} else {
    log.Printf("AuthRail call=%s result=%s",
        observation.CallDecision.Outcome, observation.ResultDecision.Outcome)
}
```

Use Go's `log` package for this example. With a healthy Observe deployment,
you receive decisions for both phases; their outcomes depend on your published
Rails. `RecordingStatus == "retained"` means AuthRail stored the check;
`"queued"` means the sidecar saved it for later delivery. Open the deployment's
Runtime history in your workspace to inspect retained decisions. A failed
check needs investigation, but still does not stop an Observe callback.

The earlier snippet uses your application's `organisationID`, `deploymentID`,
`refundOperationVersionID`, `currentStaff`, `task`, `refund`, `Receipt` and
`payments` objects. Replace them with your own reviewed configuration and
business types. It is integration code for your program, not a standalone
server. The action contract must cover these fields and identities.

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
A Policy can report `approval_required` again at the result hook. The Go adapter
releases that retained result only after a one-use permit was claimed for the
same Action. Denied, missing, replayed, or different-Action results remain
blocked after the provider callback.
The [executable HTTP handler example](examples/enforce-payment/main.go) uses a
mock provider ledger and one fixed test action key. Replace that key with a
distinct stable business key for each real effect, and derive the caller from
your authenticated application context.

On `ApprovalRequired`, keep the pending value while this process waits for a
named human decision, then call `ResumeApproval` with the original protected
operation. For a workflow crossing a request or process boundary, call
`pending.Continuation()` before claiming a permit. Encrypt and persist the
returned `ApprovalContinuation` in application-owned storage, scoped to the
authenticated user, organisation, deployment, Action and original business
request. It contains private arguments, facts and session context; do not send
it to an agent or accept a replacement supplied by an agent.

```go
var pending *authrail.ApprovalRequired
if errors.As(err, &pending) {
    continuation, snapshotErr := pending.Continuation()
    if snapshotErr != nil { return snapshotErr }
    // Encrypt and save json.Marshal(continuation) in your protected workflow store.
    // After the named reviewer approves, restore it and supply the original executor:
    // After restoring the continuation, ResumeApprovalFrom(ctx, client,
    // continuation, payInvoice) returns the result, result decision, and error.
}
```

A new client with the same deployment identity and executor key can resume
the saved call. Resumption retains its processed input and attempt ID; it
does not ask the model for replacement arguments or rerun call processors.
The SDK does not persist this state or restore the callback for you. Named
review needs the bounded application-supplied `Operation.ReviewSummary`; do
not include secrets or raw payloads in that summary.

If the permit claim response is lost, `RecoverApprovalFrom` uses the saved
continuation to read only an existing, unexpired permit for that exact Action,
input and executor. It never creates a second permit. An unavailable, expired,
mismatched or already-started permit does not run the callback. Do not blindly
retry a claim or effect. If a start receipt or provider outcome is uncertain,
inspect the Action and reconcile the provider outcome before considering any
new attempt.

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

## Supply prior session reads

For a Guard that requires string processing, register `Config.GuardHandlers`
with its exact reviewed ID, SHA-256 version, kind (`sanitize` or `transform`),
and a side-effect-free `Process(context.Context, string) (string, error)`.
Enforce reads requirements from the authenticated local sidecar, processes only
the reviewed string fields, and signs before/after digests. Result processing
happens before exposure. Missing handlers, stale plans, conflicts, errors,
and unsupported isolation block the boundary. Each handler has four seconds
or the caller's earlier cancellation. A handler that ignores cancellation may
continue locally; it must never perform business effects. Approval resumes
reuse the processed call. Observe never runs processors. These assertions do
not independently verify handler code or sandbox containment.

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

The protected application owns QuickBooks consent and its OAuth callback.
Bind the returned realm ID to the reviewed account before storing tokens in
its own encrypted, access-controlled credential store. Refresh before a read
when needed, serialize refresh per realm, and persist the newest access and
refresh tokens together before using them. Expired, revoked, or mismatched
grants produce unavailable context and require reconnection. Keep tokens,
OAuth codes, and provider response bodies away from the agent, sidecar, and
AuthRail. Stripe keys also stay in that store, scoped to the reviewed account.
The SDK consumes an application-supplied access token for one bounded read;
it does not perform consent, persist tokens, or retry an effect.

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


### Observe execution outcomes

`Observation.Call` contains the frozen original attempt after the advisory
checks complete. Pass it to `client.ReportObservedExecution(ctx, *checks.Call,
outcome)` with an `ObservedExecutionOutcome`: `Event`, the executor's stable
`ProviderIdempotencyKey`, and optional `ProviderReference`. Supported events
are `succeeded`, `failed`, `unknown`, `reconciled_succeeded`, and
`reconciled_failed`. A tool error normally needs `unknown` until the executor
can establish whether its effect happened. Never infer success from an allow
decision, and never rerun an operation to retry its receipt.

`RecordingStatus` distinguishes local durable `queued` delivery from central
`retained` evidence. A retained response supplies Action and receipt IDs.
Reporting is separate from execution and does not request a permit or change
Observe's advisory decision. Keep the original call until report delivery is
acknowledged; send only bounded references and exact input digests.

## Validate the SDK source combination

Run `go test -race ./...` for the Go SDK checks. With `authrail-sidecar` and
`authrail-sdk-node` checked out beside this repository, Node dependencies
installed, and Go module dependencies available, run:

```sh
sh scripts/check-sidecar.sh
```

This builds the Node SDK and connects both SDKs to the real sidecar HTTP
handlers. The harness generates private temporary credentials and a signed
Enforce bundle; it checks allowed call/result hooks, denied calls without an
effect, JSON-persisted approval recovery and duplicate-start blocking. The
fixture verifies the signed permit and receipt statements. It uses isolated
loopback listeners and temporary state, then removes them. It never reads
customer secrets, changes a running sidecar, calls a provider or uses tenant
records.

The control plane in this check is a fixture, so `retained` responses establish
SDK/sidecar protocol translation only. Central persistence, human review,
provider reconciliation, full interception, Docker recovery and release
compatibility require their own connected verification. String Guard handlers
do not establish isolation; source-read and extraction provenance remain
protected-application assertions. Neither SDK automatically restores callbacks,
persists application workflow state or retries a business effect.

## Continuous integration

SDK CI runs on pull requests and pushes to main and the existing feature branch.
It checks Go formatting, `go vet`, and tests with the race detector. It also
compiles an independent consumer against the committed source archive; run
`sh scripts/check-package.sh` to check that locally. This checks packaging before
each version is published; installation through the Go module proxy is checked at release.

A separate job checks this candidate with pinned Node SDK and sidecar commits,
using the actual sidecar handlers and disposable local state. Its signed
control-plane fixture does not prove tenant persistence or provider effects.
It needs no deployment secrets. CI does not create release tags.

Maintainers: see [Releasing](RELEASING.md) for checked artifacts and publication setup.
