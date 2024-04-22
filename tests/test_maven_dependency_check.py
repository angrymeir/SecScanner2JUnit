import json
import unittest

from secscanner2junit import MavenDependencyCheckParser
from secscanner2junit.config import get_config


class TestMavenDependencyCheckParser(unittest.TestCase):

    def test_basic(self):
        # given:
        input_report_path = "resources/test_maven_dependency_check/test_basic/maven-dependency-check-gitlab.json"
        missing_config_path = "resources/test_maven_dependency_check/test_basic/ss2ju-config.yml"

        report = get_report(input_report_path)
        config = get_config(missing_config_path)
        parser = MavenDependencyCheckParser(report, input_report_path, config)

        # when:
        testsuite = parser.parse()

        # then:
        self.assertEqual(len(testsuite[0].test_cases), 9)
        self.assertEqual(testsuite[0].test_cases[0].name,
                         "CVE-2023-33202 (ID: CVE-2023-33202) (Severity: Medium)")
        self.assertEqual(testsuite[0].test_cases[0].classname,
                         "MavenDependencyCheck")
        self.assertEqual(testsuite[0].test_cases[0].failures[0]["message"],
                         ('Bouncy Castle for Java before 1.73 contains a potential Denial of Service '
                          '(DoS) issue within the Bouncy Castle org.bouncycastle.openssl.PEMParser '
                          'class. This class parses OpenSSL PEM encoded streams containing X.509 '
                          'certificates, PKCS8 encoded keys, and PKCS7 objects. Parsing a file that has '
                          'crafted ASN.1 data through the PEMParser causes an OutOfMemoryError, which '
                          'can enable a denial of service attack. (For users of the FIPS Java API: '
                          'BC-FJA 1.0.2.3 and earlier are affected; BC-FJA 1.0.2.4 is fixed.)'))


def get_report(path):
    with open(path) as input_file:
        return json.load(input_file)
