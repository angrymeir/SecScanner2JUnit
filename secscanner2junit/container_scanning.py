from junit_xml import TestSuite, TestCase

from secscanner2junit.config import Config
from secscanner2junit.parser import Parser
from secscanner2junit.vulnerability import ContainerScanningVulnerability


# See following links to learn more about containers scanners and theirs output
# Example https://gitlab.com/gitlab-examples/security/security-reports/-/blob/master/samples/container-scanning.json
# https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/container-scanning-report-format.json
class ContainerScanningParser(Parser):
    def __init__(self, report, ts_name, config: Config):
        super().__init__(report, ts_name, config)
        self.p_type = "ContainerScanning"

    def parse_vulnerability(self, raw_vulnerability):
        vulnerability = ContainerScanningVulnerability(raw_vulnerability)

        tc = TestCase(name=vulnerability.get_testcase_name(),
                      classname=self.p_type,
                      file=vulnerability.get_location(),
                      elapsed_sec=1)

        tc.add_failure_info(message=vulnerability.get_description(),
                            output=vulnerability.get_output(),
                            failure_type=vulnerability.get_failure_type())
        return tc

    def parse(self):
        vulnerabilities = self.report['vulnerabilities']
        vulnerabilities = self.config.suppress(vulnerabilities)

        testsuites = []
        testcases = []

        for raw_vulnerability in vulnerabilities:
            testcases.append(self.parse_vulnerability(raw_vulnerability))

        testsuites.append(TestSuite(name=self.ts_name, test_cases=testcases))
        return testsuites
