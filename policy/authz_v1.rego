package authz_v1

import data.common
import data.policies
import data.roles
import data.tenants

default authorized = false

has_member[pol_id] {
	pol_sub := policies[pol_id].members[_]
	input_sub := input.subjects[_]
	common.subject_matches(input_sub, pol_sub)
}

has_organization[pol_id] {
   input.organizationId == policies[pol_id].organizationId
}

has_resource[[pol_id, statement_id]] {
	statement_resource := policies[pol_id].statements[statement_id].resources[_]
	common.resource_matches(input.resource, statement_resource)
}

has_resource[[pol_id, statement_id]] {
	statement_resource := policies[pol_id].statements[statement_id].resources[_]
	some i, j
    tenants[i].envs[j].clusters[_].id == input.resource
	common.resource_matches(tenants[i].envs[j].crn, statement_resource)
}

has_resource[[pol_id, statement_id]] {
	statement_resource := policies[pol_id].statements[statement_id].resources[_]
	some i
    tenants[i].envs[_].clusters[_].id == input.resource
	common.resource_matches(tenants[i].crn, statement_resource)
}

no_wildcard(a) {
	contains(a, "*") == false
}

action_matches(in, stored) {
	no_wildcard(stored)
	in == stored
}

action_matches(in, stored) = action_match(split(stored, ":"), split(in, ":"))

action_match([service, "*"], [service, _]) = true

action_match(["*", verb], [_, verb]) = true

action_match(["*"], _) = true

has_action[[pol_id, statement_id]] {
	statement_action := policies[pol_id].statements[statement_id].actions[_]
	action_matches(input.action, statement_action)
}

has_action[[pol_id, statement_id]] {
	policies[pol_id].statements[statement_id].role = role_id
	roles[role_id].actions[_] = role_action
	action_matches(input.action, role_action)
}

match[[effect, pol_id, statement_id]] {
	effect := policies[pol_id].statements[statement_id].effect
	has_organization[pol_id]
	has_member[pol_id]
	has_resource[[pol_id, statement_id]]
	has_action[[pol_id, statement_id]]
}

allow {
	match[["allow", _, _]]
}

deny {
	match[["deny", _, _]]
}

authorized {
	allow
	not deny
}