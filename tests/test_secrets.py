import json
import unittest

from secscanner2junit import SecretsParser
from secscanner2junit.config import get_config


class TestSecretsParser(unittest.TestCase):

    def test_empty_report(self):
        # given:
        input_report_path = "resources/test_secrets/test_empty/gl-secret-detection-report.json"
        missing_config_path = "resources/test_secrets/test_basic/ss2ju-config.yml"

        report = get_report(input_report_path)
        config = get_config(missing_config_path)
        parser = SecretsParser(report, input_report_path, config)

        # when:
        testsuite = parser.parse()

        # then:
        self.assertEqual(len(testsuite.pop().test_cases), 0)

    def test_basic(self):
        # given:
        input_report_path = "resources/test_secrets/test_basic/gl-secret-detection-report.json"
        missing_config_path = "resources/test_secrets/test_basic/ss2ju-config.yml"

        report = get_report(input_report_path)
        config = get_config(missing_config_path)
        parser = SecretsParser(report, input_report_path, config)

        # when:
        testsuite = parser.parse()

        # then:
        self.assertEqual(len(testsuite[0].test_cases), 3)
        self.assertEqual(testsuite[0].test_cases[0].name,
                         "SSH private key (ID: bb1eb5637b9662e74114a7b4ac7ce23a157dc57b4e2ea30deb1aa31f9ec9061e) (Severity: Critical)")
        self.assertEqual(testsuite[0].test_cases[0].classname,
                         "Secrets")
        self.assertEqual(testsuite[0].test_cases[0].file,
                         "secrets_file.txt")
        self.assertEqual(testsuite[0].test_cases[0].failures[0]["message"],
                         "SSH private key",
                         )

    def test_secret_suppression(self):
        # given:
        inpurt_report_path = "resources/test_secrets/test_secrets_suppression/gl-secret-detection-report.json"
        input_config_path = "resources/test_secrets/test_secrets_suppression/ss2ju-config.yml"

        report = get_report(inpurt_report_path)
        config = get_config(input_config_path)
        parser = SecretsParser(report, inpurt_report_path, config)

        # when:
        testsuite = parser.parse()

        # then:
        self.assertEqual(len(testsuite.pop().test_cases), 2)


def get_report(path):
    with open(path) as input_file:
        return json.load(input_file)
