# Mojaloop IAM services

The authorization side of the Ory stack: what generates a service's access
rules, what answers the gateway on every request, and what writes grants.

Ory supplies the parts. **Oathkeeper** is the gateway's policy enforcement
point, **Keto** stores the permission graph, **Kratos** manages identities and
sessions, **Hydra** issues machine tokens. What sits between them is here.

## The pieces

**`authzgen`** turns a service's annotated OpenAPI document into its
authorization artifacts. One operation is one permission, and everything else
is derived from the document's shape, so a service ships an API description and
no rules file, no permission model and no roles. The operator inside
`provisioning` runs it for every backend an HTTPRoute keys, and publishes the
composition.

**`decide`** is what Oathkeeper asks on every request. It takes the rule's
rendered payload, composes the Keto checks behind it, and answers allow or deny
along with the caller's visible resources in `X-Scope`. Stateless, read-only
Keto access, no gateway route, and the single audit point: one record per
decision either way.

**`provisioning`** is the write side, and the only thing in the platform holding
a Keto write URL. It watches the deployment's roles, separation rules and
resource names, applies every change to them as it lands, and writes each
object's verdict back onto it: a role naming a permission no service
advertises is refused instead of writing a tuple nothing will check. It
creates the first administrator on its first apply, answers admission for its
kinds, and serves the resources, roles and assignments the platform asks for.
A service that creates a resource names it, and assigns its configured roles
over it.

**`capabilities`** answers which of the permissions a caller asked about it
actually holds. Keto has no reverse index, so a UI rendering a screen or a CLI
offering a command cannot otherwise find out ahead of the call.

**`kratos-role-webhook`** writes an identity's roles into its public metadata,
and **`keto-batch-auth`** answers a list of checks in one call. Neither is on
the decision path.

## Layout

```
src/authzgen/     OpenAPI document -> rules, model, catalog, derivation table
src/operator/     routes -> documents -> one composition, published for the gateway and Keto
src/decision/     the endpoint Oathkeeper asks, and how a scope is computed
src/iam/          roles and separation rules, materialization, reconciliation, provisioning
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

# run the endpoint the gateway asks
npm start decide

# compose the cluster's routes, publish the result, keep the deployment's roles applied, and serve the IAM
npm start provisioning -- --namespace iam --publish-as authz-composed

# ...and create the first administrator on the first apply
npm start provisioning -- --namespace iam --publish-as authz-composed \
  --admin-email admin@example.test --admin-role hub-admin --admin-password "$PASSWORD"
```

`provisioning` runs against a cluster: it reads routes, gateways and the
IAM's kinds from the API server its kubeconfig names.

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
  name: dfsp-operator
spec:
  grants:
    - permission: mcm.getDFSPca                       # participant left open
    - permission: mcm.getDFSPs
      resources: { participant: all }
```

A grant names, per resource name its permission is scoped by, `all`, one id, a
list, or nothing. A role leaving a resource name open instantiates per
assignment, against `Role:dfsp-operator@participant=dfsp7`, so assignment and
revocation stay one membership edge. Each object carries a `Ready` condition
saying whether it was applied, refused and why, or is waiting for a service.

## Testing

```bash
npm test                          # unit
npm run test:integration          # against a running Ory stack
cd packages/authz && npm test     # the header contract, including round trip
```

## Documentation

- `helm/mojaloop-iam/docs/permission-model.md` — what permissions, roles and
  grants mean, and how a decision is made
- `helm/mojaloop-iam/docs/gateway-authz-architecture.md` — the network and
  enforcement path these processes sit in
