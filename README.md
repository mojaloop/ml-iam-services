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
a Keto write URL. It applies the deployment's role documents when it starts,
validating every grant against the generated catalog first, so a role naming a
permission no service advertises stops the rollout instead of writing a tuple
nothing will check; it creates the first administrator on the way; then it
serves the resources, roles and assignments the platform asks for. A service
that creates a resource names the resource and its principals, and the role
documents decide which roles that implies.

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
src/iam/          role documents, materialization, reconciliation, provisioning
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

# compose the cluster's routes, publish the result, apply the deployment's roles, then serve the IAM
npm start provisioning -- --roles ./default-roles.json --namespace iam --publish-as authz-composed

# ...and create the first administrator while applying them
npm start provisioning -- --roles ./default-roles.json --namespace iam --publish-as authz-composed \
  --admin-email admin@example.test --admin-password "$PASSWORD"
```

## What authzgen emits

| artifact | consumer |
|---|---|
| access rules | the gateway, published as `access-rules.yml` |
| Keto model | Keto, one `keto-namespaces.ts` for every service |
| catalog | the IAM, for the role UI and to validate role documents |
| derivation table | humans: one line per operation, reviewed and diffed |

The model is two shared classes and one empty class per service, because Keto
enforces namespaces but not relations and resolves role indirection with no
permit. The derivation table exists so a wrong conclusion shows up as a changed
line in review rather than a 403 in staging.

## Role documents

Deployment data, composed in a UI or in gitops, written through this service
and nowhere else.

```json
{
  "roles": {
    "hub-admin": {
      "grants": [{ "permission": "mcm.getDFSPs" },
                 { "permission": "mcm.getDFSPca", "bind": { "dfsps": "all" } }]
    },
    "dfsp-operator": {
      "params": ["dfspId"],
      "onProvision": "admin",
      "grants": [{ "permission": "mcm.getDFSPca", "bind": { "dfsps": "$dfspId" } }]
    }
  }
}
```

A grant binds each type its permission's path carries an id for, which the
catalog states as `bound`. A role with parameters instantiates per assignment,
against `Role:dfsp-operator@dfspId=dfsp7`, so assignment and revocation stay one
membership edge. `onProvision` names the principal that receives the role when
its resource appears, which is what makes onboarding need no operator step.

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
