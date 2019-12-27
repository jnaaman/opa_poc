package authz_v1

###############  has_action  ########################################

test_has_action_picks_up_INLINE_action {
	has_action[["polid", "statementid"]] with data.policies.polid.statements.statementid.actions as ["x"]
		 with input.action as "x"
}

test_has_action_ignores_other_inline_action {
	not has_action[["polid", "statementid"]] with data.policies.polid.statements.statementid.actions as ["y"]
		 with input.action as "x"
}

test_has_action_picks_up_ROLE_action {
	has_action[["polid", "statementid"]] with data.policies.polid.statements.statementid.role as "editor"
		 with data.policies.roles.editor.actions as ["x"]
		 with input.action as "x"
}

test_has_action_ignores_same_action_from_different_role {
	not has_action[["polid", "statementid"]] with data.policies.polid.statements.statementid.role as "editor"
		 with data.policies.roles.viewer.actions as ["x"]
		 with input.action as "x"
}

test_has_action_ignores_same_inline_action_from_different_statement {
	not has_action[["polid", "statement1"]] with data.policies.polid.statements as {
		{"statement1": {"action": ["y"]}},
		{"statement2": {"action": ["x"]}},
	}
		 with input.action as "x"
}

test_has_action_ignores_same_role_action_from_different_statement {
	not has_action[["polid", "statement1"]] with data.policies.polid.statements as {
		{"statement1": {"role": "editor"}},
		{"statement2": {"role": "viewer"}},
	}
		 with data.policies.roles as {
			"editor": {"actions": ["y"]},
			"viewer": {"actions": ["x"]},
		}
		 with input.action as "x"
}

###############  has_resource #######################################

test_has_resource_picks_up_resource_from_policy_statement_data {
 	has_resource[["polid", "statementid"]] with data.policies as {"polid": {"statements": {"statementid": {"resources": ["y"]}}}}
 		 with input.resource as "y"
}

###############  has_member #########################################

test_has_member_picks_up_member_from_policy_data {
	has_member.polid with data.policies as {"polid": {"members": ["z"]}}
		 with input.subjects as ["z"]
}

###############  action_matches  ####################################

test_action_matches_direct_match {
	action_matches("svc:verb", "svc:verb")
}

test_action_matches_wildcard_match {
	action_matches("svc:verb", "*")
}

test_action_matches_service_type_match {
	action_matches("svc:verb", "svc:*")
}

test_action_matches_verb_match {
	action_matches("svc:verb", "*:verb")
}

###############  base  ##############################################

test_deny_trumps_allow {
	not authorized with data.deny as true
		 with data.allow as true
}

test_authorized_defaults_to_false {
	not authorized
}

###############  allow/deny  #########################################

test_allow_matches_all_properties_with_INLINE_action_and_effect_allow {
	allow with data.policies.polid as {"members": ["x"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y"], "resources": ["z"]}}}
		 with input as {"subjects": ["x"], "action": "y", "resource": "z", "organizationId": "1234"}
}

test_allow_matches_all_properties_with_ROLE_action_and_effect_allow {
	allow with data.policies.polid as {"members": ["x"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "role": "editor", "resources": ["z"]}}}
		 with data.policies.roles.editor.actions as ["y"]
		 with input as {"subjects": ["x"], "action": "y", "resource": "z", "organizationId": "1234"}
}

test_deny_matches_all_properties_and_effect_deny {
	deny with data.policies.polid as {"members": ["x"], "organizationId": "1234", "statements": {"statementid": {"effect": "deny", "actions": ["y"], "resources": ["z"]}}}
		 with input as {"subjects": ["x"], "action": "y", "resource": "z", "organizationId": "1234"}
}


###############  authorized  #########################################

test_not_authorized_when_only_not_matching_policies_with_effect_allow_are_present {
	not authorized with data.policies.polid as {"members": ["x0"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y0"], "resources": ["z0"]}}}
		 with input as {"subjects": ["x1"], "action": "y1", "resource": "z1", "organizationId": "1234"}
}

test_authorized_when_one_among_a_group_of_members_is_present {
	authorized with data.policies.polid as {"members": ["x0", "x1"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y0"], "resources": ["z0"]}}}
		 with input as {"subjects": ["x1"], "action": "y0", "resource": "z0", "organizationId": "1234"}
}

test_authorized_when_not_all_subjects_are_present_as_members {
	authorized with data.policies.polid as {"members": ["x1"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y0"], "resources": ["z0"]}}}
		 with input as {"subjects": ["x1", "x2"], "action": "y0", "resource": "z0", "organizationId": "1234"}
}

test_authorized_when_not_matching_policy_with_effect_deny_is_present {
	authorized with data.policies.polid as {"members": ["x"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y"], "resources": ["z"]}}}
		 with data.policies.polid1 as {"members": ["x0"], "organizationId": "1234", "statements": {"statementid1": {"effect": "deny", "actions": ["y0"], "resources": ["z0"]}}}
		 with input as {"subjects": ["x"], "action": "y", "resource": "z", "organizationId": "1234"}
}

test_not_authorized_when_any_matching_policy_with_effect_deny_is_present {
	not authorized with data.policies.polid0 as {"members": ["x"], "organizationId": "1234", "statements": {"statementid0": {"effect": "allow", "actions": ["y"], "resources": ["z"]}}}
		 with data.policies.polid1 as {"members": ["x"], "organizationId": "1234", "statements": {"statementid1": {"effect": "deny", "actions": ["y"], "resources": ["z"]}}}
		 with input as {"subjects": ["x"], "action": "y", "resource": "z", "organizationId": "1234"}
}

test_not_authorized_matches_all_properties_except_organization {
	not authorized with data.policies.polid as {"members": ["x"], "organizationId": "w", "statements": {"statementid": {"effect": "allow", "actions": ["y"], "resources": ["z"]}}}
		 with input as {"subjects": ["x"], "action": "y", "resource": "z", "organizationId": "w1"}
}

test_authorized_when_resource_is_hierarchical_env {
	authorized with data.policies.polid as {"members": ["x1"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y0"], "resources": ["crn://e0"]}}}
	     with data.policies.tenants as [ { "id": "o0", "envs": [ { "id": "e0", "crn": "crn://e0", "clusters" : [ { "id": "z0" } ] } ] } ]
		 with input as {"subjects": ["x1"], "action": "y0", "resource": "z0", "organizationId": "1234"}
}

test_not_authorized_when_resource_is_hierarchical_env {
	not authorized with data.policies.polid as {"members": ["x1"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y0"], "resources": ["crn://e0"]}}}
	     with data.tenants as [ { "id": "o1", "envs": [ { "id": "e1", "crn": "crn://e1", "clusters" : [ { "id": "z0" } ] } ] } ]
		 with input as {"subjects": ["x1"], "action": "y0", "resource": "z0", "organizationId": "1234"}
}

test_authorized_when_resource_is_hierarchical_org {
	authorized with data.policies.polid as {"members": ["x1"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y0"], "resources": ["crn://o0"]}}}
	     with data.policies.tenants as [ { "id": "o0", "crn": "crn://o0", "envs": [ { "id": "e0", "clusters" : [ { "id": "z0" } ] } ] } ]
		 with input as {"subjects": ["x1"], "action": "y0", "resource": "z0", "organizationId": "1234"}
}


test_not_authorized_when_resource_is_hierarchical_org {
	not authorized with data.policies.polid as {"members": ["x1"], "organizationId": "1234", "statements": {"statementid": {"effect": "allow", "actions": ["y0"], "resources": ["crn://o0"]}}}
	     with data.tenants as [ { "id": "o1", "crn": "crn://o1", "envs": [ { "id": "e0", "clusters" : [ { "id": "z0" } ] } ] } ]
		 with input as {"subjects": ["x1"], "action": "y0", "resource": "z0", "organizationId": "1234"}
}


test_authorized_sample_user_1 {
	authorized with input as {
    "subjects": [
        "user:1"
    ],
    "action": "kafka:consumeTopic",
    "resource": "crn://confluent.cloud/env=dev/kafka=k1/topic=topic1",
    "organizationId": 901
	}
}