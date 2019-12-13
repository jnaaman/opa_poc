# OPA Authz Policy

This folder contains our OPA policy definitions.
For information on OPA see:

- [open-policy-agent on github](https://github.com/open-policy-agent/opa/)
- [OPA main site](https://www.openpolicyagent.org/)

## Terminology Caveat

When it comes to OPA, _its policies_ are different from _`authz-service`'s policies_:

1. The latter--ours--are the first class entities `authz-service` works with: documents containing a name, metadata, a subject, as well as set of (resource, action, effect) tuples (or "statements").
2. The former--OPA policies--are the static Rego-code documents driving policy decisions.

## Install OPA REPL

Load your rego and policies upon invocation of the OPA REPL utility.
[Download OPA](https://www.openpolicyagent.org/docs/get-started.html#prerequisites) or install it via homebrew (`brew install opa`).


### Run with Policy

NB: Assumes running from this directory; just adjust all paths if you want to start in a different directory.
Note that the input still uses subjects as the field instead of members.

```opa
$ opa run -w authz_v1.rego common.rego policies:../examples/policies.json
OPA 0.9.2 (commit 9fbff4c3, built at 2018-09-24T16:12:26Z)

> data.authz_v1.authorized
false
# This matches against an action/resource from a statement in a policy.
> data.authz_v1.authorized with input as { "subjects": [ "team:local:admins" ], "action": "iam:teams:create", "resource": "iam:teams" }
true
> data.authz_v1.authorized with input as { "subjects": [ "team:local:admins" ], "action": "iam:teams:create", "resource": "iam:users" }
false
# This matches against an action/resource from a statement in a policy.
> data.authz_v1.authorized with input as { "subjects": [ "team:local:admins" ], "action": "infra:nodes:delete", "resource": "infra:nodes" }
true
>
```

## Running OPA Unit Tests

From the current directory, run unit tests with:

```console
$ opa test authz_v1.rego common.rego authz_v1_test.rego
```