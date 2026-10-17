# AuthRail Go SDK

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
    SessionID: task.ID,
    ResourceID: refund.InvoiceID,
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
session and resource lookup before calling `Observe`. Keep the signing key and
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

**Current scope:** Observe checks Go structs or maps sent to a sidecar on the
same host. Decisions are advisory. This version does not stop actions or handle
approvals. AuthRail retains covered reports when reachable; a missing report
remains visible as a recording gap.
