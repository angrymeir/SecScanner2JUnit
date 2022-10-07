import json
import unittest

from secscanner2junit import ContainerScanningParser
from secscanner2junit.config import get_config


class TestContainerScanningParser(unittest.TestCase):

    def test_basic(self):
        # given:
        input_report_path = "resources/test_container_scanning/test_basic/gl-container-scanning-report.json"
        missing_config_path = "resources/test_container_scanning/test_basic/ss2ju-config.yml"

        report = get_report(input_report_path)
        config = get_config(missing_config_path)
        parser = ContainerScanningParser(report, input_report_path, config)

        # when:
        testsuite = parser.parse()

        # then:
        self.assertEqual(len(testsuite[0].test_cases), 11)
        self.assertEqual(testsuite[0].test_cases[0].name,
                         "CVE-2022-32206 (ID: 2ca5d70e4698a5b136fa99b0f0cd2f599f7bb65b) (Severity: Medium)")
        self.assertEqual(testsuite[0].test_cases[0].classname,
                         "ContainerScanning")
        self.assertEqual(testsuite[0].test_cases[0].file,
                         "nexus.com.pl/springboot-example:b9916511812d32271de8b9cfcaa2a5e03560973e")
        self.assertEqual(testsuite[0].test_cases[0].failures[0]["message"],
                         "curl < 7.84.0 supports \"chained\" HTTP compression algorithms, meaning that a serverresponse can be compressed multiple times and potentially with different algorithms. The number of acceptable \"links\" in this \"decompression chain\" was unbounded, allowing a malicious server to insert a virtually unlimited number of compression steps.The use of such a decompression chain could result in a \"malloc bomb\", makingcurl end up spending enormous amounts of allocated heap memory, or trying toand returning out of memory errors.",
                         )


def get_report(path):
    with open(path) as input_file:
        return json.load(input_file)
