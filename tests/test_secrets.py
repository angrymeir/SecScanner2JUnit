import json
import unittest

from secscanner2junit import SecretsParser
from secscanner2junit.config import get_config


class TestSecrets(unittest.TestCase):

    def test_secret_name(self):
        # given:
        # https://gitlab.com/gitlab-examples/security/security-reports/-/blob/master/samples/secret-detection.json
        input_report_path = "resources/test_secrets/test_secret_suppression/gl-secret-detection.json"
        input_config_path = "resources/test_secrets/test_secret_name/no-config.yml"

        report = get_report(input_report_path)
        config = get_config(input_config_path)
        parser = SecretsParser(report, input_report_path, config)

        # when:
        testsuite = parser.parse()

        # then:
        testsuite = testsuite.pop()
        self.assertEqual(len(testsuite.test_cases), 5)

        testcase = testsuite.test_cases.pop()
        # The test case name must be unique or it will be deduplicated even
        # when it describes a different occurrence. (line number etc.)
        self.assertEqual(testcase.name, 'PGP private key (ID: bc315b03465e0140cc44ab687eff5c0c6848f0e648ac633f476757324f3d8136) (Severity: Critical)')


    def test_secret_suppression(self):
        # given:
        # https://gitlab.com/gitlab-examples/security/security-reports/-/blob/master/samples/secret-detection.json
        input_report_path = "resources/test_secrets/test_secret_suppression/gl-secret-detection.json"
        input_config_path = "resources/test_secrets/test_secret_suppression/ss2ju-config.yml"

        report = get_report(input_report_path)
        config = get_config(input_config_path)
        parser = SecretsParser(report, input_report_path, config)

        # when:
        testsuite = parser.parse()

        # then:
        self.assertEqual(len(testsuite.pop().test_cases), 4)


def get_report(path):
    with open(path) as input_file:
        return json.load(input_file)
