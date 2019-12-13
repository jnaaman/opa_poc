# Package common contains functions and rules that are shared between v1 and v2
# of our rego logic
package rego.common

wildcard(a) {
	contains(a, "*")
}

# Check that it does not contains "*" AND that it is not a solitary "*".
# Note: The latter is done so that we don't end up with 'input.resource = *'
# rules in our partial results.
# Note that we avoid "not", which hinders partial result optimizations, see
# https://github.com/open-policy-agent/opa/issues/709.
not_wildcard(a) {
	contains(a, "*") == false
	a != "*"
}

# This supports these business rules:
# (a) A wildcard may only occur in the value
# (b) A wildcard may appear anywhere in value
# (c) Only 1 wildcard in the value
wildcard_match(a, b) {
	startswith(a,  substring(b, 0, indexof(b, "*")))
	endswith(a, substring(b, indexof(b,"*")+1,-1))
	count(a) >= count(b)-1  # avoids duplicate counting prefix and suffix
}

trim_and_split(s) = x {
    t := trim(s, "crn://")
    x := split(t, "/")
}

#
# Resource matching
#
key_match(in, stored) {
    in == stored
}

value_match(in, stored) {
	not_wildcard(stored)
	in == stored
}

value_match(in, stored) {
	wildcard(stored)
	wildcard_match(in, stored)
}

section_match(in, stored) {
   in == stored
}

section_match(in, stored) {
  contains(in, "=")
  contains(stored, "=")
  in_a := split(in, "=")
  stored_a := split(stored, "=")
  key_match(in_a[0], stored_a[0])
  value_match(in_a[1], stored_a[1])
}

resource_matches(in, stored) {
  in_a := trim_and_split(in)
  stored_a := trim_and_split(stored)

  count(in_a) >= count(stored_a)
  count({i | section_match(in_a[i],stored_a[i])}) == count(stored_a)

}

resource_matches(_, "*") = true

#
# Subject matching
#
subject_matches(in, stored) {
	not_wildcard(stored)
	in == stored
}

subject_matches(in, stored) {
	wildcard(stored)
	wildcard_match(in, stored)
}

subject_matches(_, "*") = true