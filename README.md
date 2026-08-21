# pubky-fiat-verifier

A payment **verifier gateway** for the [Locks](https://github.com/pubky/locks) entitlement
layer. It speaks the exact signed wire contract the Lock Server already uses to talk to a
Paykit Server (`POST /invoices`, `POST /transactions/status`, ed25519 over canonical JSON
in `X-Paykit-Signature`), and dispatches on the content lock's payment criterion `asset`:

- **`BTC`** → the signed call is forwarded **verbatim** (original body + original
  signature) to the real Paykit Server. The gateway holds no signing key of its own on
  this path; the Paykit Server keeps trusting the Lock Server's pinned key, and the
  signature covers only the canonical body, so pass-through is contract-exact.
- **`USD`** (fiat) → a Stripe Checkout Session is created, idempotently keyed to the
  verification task, and the correlation is settled through Stripe **test mode**.

This proves the design claim in the marketplace's `fiat-rails-design.md`: Locks is a
payment-agnostic entitlement layer, and a fiat rail plugs into the same verifier
contract, the same lifecycle, and the same marketplace verification loop with **zero
upstream changes** to Locks, Paykit Server, or marketplace-service.

## Topology

```
                                  ┌──────────────────────────┐
Lock Server ──[paykit].server_url─►      fiat-verifier       │
 (signed HTTP, ed25519 pinned)    │  dispatch on criterion   │
                                  │          asset           │
                                  │   BTC ──────────────────────► paykit-server (unchanged,
                                  │   (verbatim body + sig)  │     private networking)
                                  │                          │
                                  │   USD → Stripe processor ────► api.stripe.com (TEST mode)
                                  │     · Checkout Session   │
                                  │     · webhook = hint     ◄──── Stripe webhooks (public domain)
                                  │     · API pull = truth   │
                                  │     · settlement delay   │
                                  └──────────┬───────────────┘
                                             │
Buyer ── POST /checkout-sessions ────────────┘   (fetches the hosted checkout URL;
         {creator, bundle_id}                     bundle id is bearer material)
```

The Lock Server has exactly one payment backend URL, which is why this is a gateway and
not a second backend: one URL, all rails. Cutover is an operator env change
(`LOCKS_PAYKIT_SERVER_URL` on the Lock Server) — no code changes anywhere upstream.

## Wire surface

| Endpoint | Auth | Behavior |
| --- | --- | --- |
| `POST /invoices` | `X-Paykit-Signature` (pinned Lock Server key; canonical-JSON strict body) | Fetch the content lock from the creator's homeserver (public Pubky read), parse the `paykit-payment` criterion, dispatch by `asset`. BTC → proxy. Fiat → create Checkout Session, persist correlation, `204`. Exact replay → `204` (idempotent). Same identity, different binding → `409`. |
| `POST /transactions/status` | same | Unknown or BTC correlation → proxy (the real Paykit Server owns every BTC invoice, including all pre-cutover ones). Fiat → answered from local state, advanced **only** by verified API pulls. |
| `POST /checkout-sessions` | possession of `{creator, bundle_id}` (bearer material), rate-limited | Returns `{checkout_url, processor, expires_at}`. Idempotent; re-mints if the processor session expired. `404` unknown/BTC, `409` once paid. |
| `POST /webhooks/stripe` | `Stripe-Signature` (HMAC over raw body, ±300s tolerance, deduped by event id) | A **hint, never a fact**: schedules an API pull. `checkout.session.completed` / `async_payment_succeeded` → pull the session. `charge.refunded` / `charge.dispute.created` → pull the charge, and only a corroborating pull marks the correlation reversed. |
| `GET /health` | none | DB + processor wiring status. |

### Fiat state mapping (settlement delay = fiat confirmations)

| Internal state | Reported to the Lock Server |
| --- | --- |
| created (no completed checkout) | `undetected, 0, false` |
| paid (API pull verified), inside settlement delay | `detected, 0, amount_matched` |
| paid, delay elapsed, fresh re-pull still paid | `confirmed, FIAT_SYNTHESIZED_CONFIRMATIONS, true` |
| reversed/disputed before completion (pull-verified) | `undetected, 0, false` — never promoted |

There is no early-failure transition in the Locks contract: an abandoned checkout leaves
the task pending until the marketplace payment window and task expiry lapse, exactly as
an unpaid Bitcoin invoice does.

The buyer's payment instruction cannot ride the invoice response (the Lock Server
discards the response body), which is why `/checkout-sessions` exists: after proof-bundle
submission the client fetches the checkout URL with the same `{creator, bundle_id}` pair
it already holds and opens it. That client work is Phase 2; the data flows today.

## Trust model, stated bluntly

| Property | Bitcoin via Paykit (proxied) | Card via Stripe (this service) |
| --- | --- | --- |
| Who attests payment | Paykit Server operator reading its own Electrum view of the chain | fiat-verifier operator reading Stripe's API |
| Can the attestor lie? | Yes — but anyone can independently verify on-chain | Yes — and only Stripe + the seller's dashboard can contradict it |
| Reversible after Locks `completed`? | No (N confirmations) | **Yes** — chargebacks up to ~120 days; lands in the marketplace dispute flow, not in Locks |
| Who sees the buyer | Paykit operator sees reader pubky ↔ invoice | Stripe sees the buyer's card identity; this service sees pubky ↔ session linkage |
| Settlement finality signal | Block confirmations (objective) | A settlement-delay timer this service imposes (policy, not physics) |
| What Locks itself trusts | Identical in both cases: the Lock Server operator and its configured backend URL |

The operator of this service can see who paid for what and could falsely report payment
status in either direction. Mitigation is operational (structured logs, the seller's own
Stripe dashboard as a cross-check), not cryptographic — the same trust class as the
Paykit Server operator, with larger identity exposure because Stripe knows the buyer's
legal identity. Privacy-conscious buyers should use the Bitcoin rail.

## Configuration

All configuration is environment variables. No secret ever lives in this repo.

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `FIAT_TRUSTED_LOCKS_PUBLIC_KEY` | yes | — | The Lock Server's canonical pubky-prefixed public key (same value as the Paykit Server's `[locks] trusted_public_key`). |
| `FIAT_DATABASE_URL` | yes | — | Postgres URL (correlations + webhook dedupe). |
| `FIAT_PAYKIT_SERVER_URL` | no | `http://paykit-server.railway.internal:3001` | The real Paykit Server for BTC pass-through. |
| `FIAT_LISTEN_ADDR` / `PORT` | no | `[::]:3002` | Bind address (Railway injects `PORT`). |
| `STRIPE_SECRET_KEY` | no | — | **Test-mode** secret key (`sk_test_...`). Absent ⇒ fiat path fails closed with 503; BTC proxying is unaffected. |
| `STRIPE_WEBHOOK_SECRET` | no | — | Webhook signing secret (`whsec_...`). Absent ⇒ webhooks answer 503 and detection relies purely on API polling (the Lock Server's ~30s status poll and the slow poll both pull). |
| `FIAT_LIVE_MODE` | no | unset | A live-looking Stripe key refuses to boot unless this is exactly `true`. Staging = test keys only, forever. |
| `FIAT_SETTLEMENT_DELAY_SECONDS` | no | `300` | Anti-chargeback rest period between `detected` and `confirmed`. |
| `FIAT_SYNTHESIZED_CONFIRMATIONS` | no | `1` | Reported once confirmed; must be ≥ the Lock Server's `[paykit] minimum_confirmations`. |
| `FIAT_ALLOWED_ASSETS` | no | `USD` | Comma-separated uppercase fiat codes accepted on the fiat path (never BTC). |
| `FIAT_CHECKOUT_SUCCESS_URL` / `FIAT_CHECKOUT_CANCEL_URL` | no | staging app URLs | Stripe Checkout redirect targets. Redirects are buyer-attested and carry no state; the Locks lifecycle is the only truth. |
| `FIAT_POLL_INTERVAL_SECONDS` | no | `60` | Slow-poll interval over open fiat correlations (lost-webhook recovery). |
| `FIAT_CHECKOUT_RATE_PER_SECOND` / `FIAT_CHECKOUT_RATE_BURST` | no | `5` / `20` | Token bucket for `/checkout-sessions`. |
| `STRIPE_API_BASE` | no | `https://api.stripe.com` | Overridable for tests only. |

## Runbook

### Deploy (Railway, project `pubky-marketplace-staging`)

```bash
railway add --service fiat-verifier            # once
railway add --database postgres                # once (service "fiat-postgres")
# set variables per the table above, then:
railway up --service fiat-verifier --detach
railway domain --service fiat-verifier         # public domain (Stripe webhooks need one)
```

### Enable Stripe test mode

1. Set `STRIPE_SECRET_KEY` to a **test-mode** secret key.
2. Create the webhook endpoint against the public domain and capture its secret:

```bash
curl -s https://api.stripe.com/v1/webhook_endpoints \
  -u "$STRIPE_SECRET_KEY:" \
  -d "url=https://<fiat-verifier-domain>/webhooks/stripe" \
  -d "enabled_events[]=checkout.session.completed" \
  -d "enabled_events[]=checkout.session.async_payment_succeeded" \
  -d "enabled_events[]=charge.refunded" \
  -d "enabled_events[]=charge.dispute.created"
# → response field "secret" is STRIPE_WEBHOOK_SECRET
```

3. Redeploy. `/health` reports `stripe_enabled` and `stripe_webhook_configured`.

### Cutover / rollback

Point the Lock Server at the gateway (this is the only change anywhere):

```bash
railway variables --service locks-server \
  --set "LOCKS_PAYKIT_SERVER_URL=http://fiat-verifier.railway.internal:<port>"
# redeploy locks-server, then re-run the BTC live purchase proof
```

Rollback is the same variable set back to `http://paykit-server.railway.internal:3001`.

### Observing a fiat purchase

Structured JSON logs carry the full lifecycle: `dispatch:` lines on invoices,
`fiat payment detected (verified by API pull)`, and
`fiat payment confirmed (settlement delay elapsed, re-pull verified)`. Nothing moves
state except a pull: grep for those two messages when auditing an entitlement.

## Development

```bash
cargo test        # 48 tests: signature verification, dispatch, idempotency,
                  # webhook-vs-pull disagreement (pull wins), delay window,
                  # re-mint, reversal suppression
cargo build --release
```

Unit tests run against an in-memory store, a mock Stripe API, and a mock Paykit Server;
signatures in tests are real ed25519 over canonical JSON. The live staging proof uses a
real Stripe test-mode payment — never a mock.

## Known limitations (recorded, not hidden)

- On the wire, a Stripe-settled entitlement still says `verifier_type: "paykit-payment"`
  — a semantic misnomer, not a trust change (the label was never a trust statement).
  The upstream proposal for a generic `external-payment` verifier type removes it.
- `confirmations` for fiat is synthesized to satisfy the existing satisfaction rule; the
  mechanism (the delay really elapsed) is honest, the unit is not.
- Post-completion chargebacks land in the marketplace dispute flow (operator-manual in
  this phase); Locks has no un-complete transition, deliberately.
- Seller onboarding (Stripe Connect) is a later phase: this deployment settles into the
  operator-configured Stripe test account, marked staging-only.
