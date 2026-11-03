# Mojaloop IAM services

The authorization side of the Ory stack: what generates a service's access
rules, what answers the gateway on every request, and what writes grants.

Ory supplies the parts. **Oathkeeper** is the gateway's policy enforcement
point, **Keto** stores the permission graph, **Kratos** manages identities and
sessions, **Hydra** issues machine tokens. What sits between them is here.

## The pieces

One image, three processes.

**`decide`** is what Oathkeeper asks on every request. It takes the rule's
rendered payload, composes the Keto checks behind it, and answers allow or deny
along with the caller's visible resources in `X-Scope`. Stateless, read-only
Keto access, no gateway route, and the single audit point: one record per
decision either way.

**`controller`** composes and writes. It reads every HTTPRoute the IAM is
named on and the OpenAPI document of each backend, and publishes the access
rules and the Keto model. It applies the deployment's roles, separation rules
and resource names as they change, writing each object's verdict back onto it,
answers admission for its kinds, and is the single writer of grants and
memberships: every assignment is checked against the separation rules and
against what the one handing it out holds, one after another. Started with
`--lease <name>`, its replicas elect that writer through a Lease: every
replica composes and answers admission, the leader alone writes, and the
others hand it the writes and composition reads they receive. A leader that
stops releases the lease and another takes it on the change.

**`api`** serves two ports. The public one, through the gateway, is the IAM's
own API for people and the UIs they use: the catalog, roles composed here,
who holds what, and which permissions the caller holds. Each of its operations
is a permission like any other service's, and nobody hands out access they do
not hold unless their scope for the operation names it. The internal one,
reachable only by the services a network rule names, is how a service records
a resource it created, creates the people and machine clients that operate it,
and assigns them roles. Nothing outside the IAM talks to Kratos or Hydra.

## Layout

```
src/authzgen/     OpenAPI document -> rules, model, catalog, derivation table
src/operator/     routes -> documents -> one composition; admission for the four kinds
src/decision/     the endpoint Oathkeeper asks, and how a scope is computed
src/iam/          roles, separation, materialization, holdings, the permission history
src/controller/   the controller process and its API
src/api/          the api process; public.yaml, internal.yaml, controller.yaml
packages/authz/   the X-Scope contract, published for services to install
```

`packages/authz` is a separate zero-dependency package on purpose. Services
install it to read the header; this repository uses it to write the header. One
definition, with a round-trip test, so the two cannot drift. Nothing with
dependencies belongs in it, or every service inherits this repository's
toolchain.

## Quick start

```bash
npm install
npm run build

# the endpoint the gateway asks
npm start decide

# compose the cluster's routes, keep the deployment's roles applied, write assignments
npm start controller -- --namespace iam --publish-as authz-published \
  --announce-as authz-composition --history-as authz-history \
  --admin-email admin@example.test --admin-role hub-admin

# the public and internal APIs
npm start api -- --namespace iam --announced-in authz-composition --controller-url http://localhost:3003
```

`controller` and `api` run against a cluster: they read routes, gateways and
the IAM's kinds from the API server their kubeconfig names. `npm start -- <command> --help`
lists every option.

## When a service changes its API

The controller keeps every permission the deployment has ever composed, in
the `--history-as` ConfigMap. When one disappears from a composed service, it
is renamed to the operation declaring `x-authz.replaces` for it, or to a new
one at the same method and path; otherwise it is removed. A grant under a
renamed permission holds under the new name and a removed one is dropped, each
with a warning on the role's status, an Event on the service's routes and an
entry in the public `/state`; a role the IAM keeps itself is moved to the new
name. A name no catalog ever had is refused as a typo.

## What authzgen emits

| artifact | consumer |
|---|---|
| access rules | the gateway, published as `access-rules.yml` |
| Keto model | Keto, one `keto-namespaces.ts` for every service |
| catalog | the IAM, for the role UI and to validate roles |
| derivation table | humans: one line per operation, reviewed and diffed |

The model is two shared classes and one empty class per service, because Keto
enforces namespaces but not relations and resolves role indirection with no
permit. The derivation table exists so a wrong conclusion shows up as a changed
line in review rather than a 403 in staging.

## The deployment's data

Four kinds in `iam.mojaloop.io/v1`, in any namespace, each name unique across
the cluster:

| kind | holds |
|---|---|
| `AuthzRole` | one role: a set of grants |
| `AuthzSeparation` | groups of permissions no one subject may hold across |
| `AuthzResourceName` | one name for a thing services spell differently |
| `AuthzDocument` | the document of a backend that serves none |

```yaml
apiVersion: iam.mojaloop.io/v1
kind: AuthzRole
metadata:
  name: widget-operator
spec:
  grants:
    - permission: example.getWidgetCa                 # widget left open
    - permission: example.getWidgets
      resources: { widget: $all }
```

A role can also carry `heldBy: authenticated`: every signed-in subject holds
it, and nobody is assigned it. A role names each permission once, and a grant
fixes each resource name its permission is scoped by to `$all` or leaves it
open; only the IAM's own names, `role` and `permission`, take ids. A role
leaving a resource name open instantiates per assignment, against
`Role:widget-operator@widget=w7`, so assignment and revocation stay one
membership edge. Each object carries a `Ready` condition
saying whether it was applied, refused and why, or is waiting for a service.

## Testing

```bash
npm test                          # unit
npm run test:integration          # starts Keto, Kratos and Hydra in compose, runs against them
cd packages/authz && npm test     # the header contract, including round trip
```

## Documentation

- `helm/mojaloop-iam/docs/permission-model.md` — what permissions, roles and
  grants mean, and how a decision is made
- `helm/mojaloop-iam/docs/gateway-authz-architecture.md` — the network and
  enforcement path these processes sit in
