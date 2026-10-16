# AuthRail SDK for Go

Connect a Go tool or workflow function to the AuthRail sidecar. The SDK sends
the proposed call and its result to the sidecar, where the Rails selected for
your deployment are evaluated.

## Observe a function

Create a client with the local sidecar address and adapter secret. Wrap a
function with `Observe`, passing the exact reviewed Operation Version, a UUID
request ID, a stable action key, and JSON object arguments. `Observe` runs your
function once and returns its original result and error without waiting for
AuthRail. The returned channel delivers the call and result decisions when
they are ready.

```go
client, err := authrail.NewClient("http://127.0.0.1:7078", adapterToken, nil)
if err != nil { return err }

result, decisions, toolErr := client.Observe(ctx, authrail.Call{
    RequestID:          requestID,
    OperationVersionID: operationVersionID,
    ActionKey:          workflowActionKey,
    Arguments:          json.RawMessage(`{"invoiceId":"inv_123"}`),
}, func(ctx context.Context) (json.RawMessage, error) {
    return issueInvoice(ctx)
})

// Continue the customer's workflow with result and toolErr.
// Read <-decisions separately for Observe diagnostics.
_ = result
_ = decisions
_ = toolErr
```

Use the same action key when retrying the same business action. The sidecar
currently checks its shape but does not yet store or deduplicate Actions. Keep
the adapter secret in the protected application, away from the agent and its
tools. The sidecar's deployment credential is separate and never belongs in
this SDK.

This package currently supports Observe checks for JSON object calls and
results on the same host as the sidecar. It does not block a call, apply an
approval, or claim enforcement. A missing sidecar decision is reported through
the decisions channel; it does not change the function's result.
