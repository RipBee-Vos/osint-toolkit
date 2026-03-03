import unittest

from osint import domain_matches, is_in_scope


class ScopeMatchingTests(unittest.TestCase):
    def test_wildcard_allows_apex_and_subdomain(self):
        self.assertTrue(domain_matches("example.com", set(), {"example.com"}))
        self.assertTrue(domain_matches("a.example.com", set(), {"example.com"}))

    def test_deny_wildcard_covers_apex_and_subdomain(self):
        self.assertTrue(domain_matches("example.com", set(), {"example.com"}))
        self.assertTrue(domain_matches("a.example.com", set(), {"example.com"}))

    def test_deny_precedence_over_allow_pattern_overlap(self):
        scope = {
            "allow_domains": {"example.com"},
            "allow_wildcards": set(),
            "allow_ips": set(),
            "allow_cidrs": [],
            "deny_domains": set(),
            "deny_wildcards": {"example.com"},
            "deny_ips": set(),
            "deny_cidrs": [],
        }
        ok, reason = is_in_scope("a.example.com", scope)
        self.assertFalse(ok)
        self.assertEqual(reason, "DENY rule matched")

    def test_allow_domain_matches_subdomain(self):
        self.assertTrue(domain_matches("sub.example.com", {"example.com"}, set()))


if __name__ == "__main__":
    unittest.main()
