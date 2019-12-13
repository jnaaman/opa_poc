package rego.common.test

import data.rego.common

test_wild_card_match_01 {
    wildcard_match("cat", "c*t")
}

test_wild_card_match_02 {
    wildcard_match("cat", "*cat")
}

test_wild_card_match_03 {
    wildcard_match("cat", "c*")
}

test_wild_card_match_04 {
    not wildcard_match("dog", "c*t")
}

test_wild_card_match_05 {
    not wildcard_match("cat", "ca*at")
}

test_section_match_01 {
    section_match("abcdefg", "abcdefg")
}

test_sectionmatch_02 {
    section_match("k=v", "k=v")
}

test_section_match_03 {
    section_match("k=v1", "k=*")
}

test_section_match_04 {
    not section_match("k=v1", "k=x*")
}


test_resource_matches_exact_simple {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234", "crn://confluent.cloud/kafka=lkc-1234")
}

test_resource_matches_exact_01 {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=events", "crn://confluent.cloud/kafka=lkc-1234/topic=events")
}

test_resource_matches_exact_02 {
	not resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=events", "crn://confluent.cloud/kafka=lkc-1234/topic=abc")
}

test_resource_matches_exact_03 {
	not resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=events", "crn://confluent.cloud/kafka=psc-1234")
}

test_resource_matches_exact_04 {
	not resource_matches("crn://confluent.cloud/kafka=lkc-1234", "crn://confluent.cloud/kafka=lkc-1234/topic=abc")
}

test_resource_matches_wildcard_namespace_01 {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234", "*")
}

test_resource_matches_wildcard_namespace_02 {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=events", "*")
}

test_resource_matches_wildcard_name_01 {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=abc/subtopic=def.events", "crn://confluent.cloud/kafka=*")
}

test_resource_matches_wildcard_name_02 {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=abc", "crn://confluent.cloud/kafka=lkc-*")
}

test_resource_matches_wildcard_name_03 {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=abc", "crn://confluent.cloud/kafka=*/topic=a*")
}

test_resource_matches_wildcard_name_04 {
	resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=abc", "crn://confluent.cloud/kafka=*/topic=abc")
}

test_resource_matches_wildcard_name_05 {
	not resource_matches("crn://confluent.cloud/kafka=lkc-1234/topic=abc", "crn://confluent.cloud/kafka=psc-*")
}
