import unittest
from opencap import *


class TestOpencap(unittest.TestCase):

    def testGetHost(self):
        host, dnssec = getHost("ogdolo.com")
        self.assertEqual("cap.ogdolo.com", host)
        self.assertTrue(dnssec)

        host, dnssec = getHost("google.com")
        self.assertEqual("", host)
        self.assertFalse(dnssec)

    def testValidateUsername(self):
        newName, valid = validateUsername("lane.c.Wagner")
        self.assertTrue(valid)

        newName, valid = validateUsername("lane-c-wail")
        self.assertTrue(valid)

        newName, valid = validateUsername("kvothe435245")
        self.assertTrue(valid)

        newName, valid = validateUsername("ner@gail.com")
        self.assertFalse(valid)

        newName, valid = validateUsername(
            "fdasdilfsudfgshghgjghfjjhghjghjgjhgjghjhjidfsbfibkfjk")
        self.assertFalse(valid)

        newName, valid = validateUsername("")
        self.assertFalse(valid)

    def testValidateDomain(self):
        domain = "ogdolo.com"
        valid = validateDomain(domain)
        self.assertTrue(valid)

        domain = "ogdolo.co"
        valid = validateDomain(domain)
        self.assertTrue(valid)

        domain = "ogdolo.bump"
        valid = validateDomain(domain)
        self.assertTrue(valid)

        domain = "com"
        valid = validateDomain(domain)
        self.assertFalse(valid)

        domain = "ogdolo."
        valid = validateDomain(domain)
        self.assertFalse(valid)

        domain = "ogdolo.b"
        valid = validateDomain(domain)
        self.assertFalse(valid)

    def testValidateAlias(self):
        username, domain = validateAlias("donate$ogdolo.com")
        self.assertEqual("donate", username)
        self.assertEqual("ogdolo.com", domain)

        username, domain = validateAlias("lane$ogdolo.com")
        self.assertEqual("lane", username)
        self.assertEqual("ogdolo.com", domain)

        username, domain = validateAlias("donateogdolo.com")
        self.assertEqual("", username)
        self.assertEqual("", domain)

        username, domain = validateAlias("donateogd$olocom")
        self.assertEqual("", username)
        self.assertEqual("", domain)

        username, domain = validateAlias("donateogdolocom")
        self.assertEqual("", username)
        self.assertEqual("", domain)

        username, domain = validateAlias("donateogdolo$com.")
        self.assertEqual("", username)
        self.assertEqual("", domain)

        domain, username = validateAlias("ogdolo.com")
        self.assertEqual("", username)
        self.assertEqual("", domain)

        domain, username = validateAlias("lane@ogdolo@.com")
        self.assertEqual("", username)
        self.assertEqual("", domain)


if __name__ == '__main__':
    unittest.main()
