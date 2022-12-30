from junit_xml import TestSuite, TestCase

from secscanner2junit.config import Config
from secscanner2junit.parser import Parser
from secscanner2junit.vulnerability import SastVulnerability


# See following links to learn more about sast scanners and theirs output
# https://docs.gitlab.com/ee/user/application_security/sast/analyzers.html#data-provided-by-analyzers
# https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/sast-report-format.json
class SastParser(Parser):
    def __init__(self, report, ts_name, config: Config):
        super().__init__(report, ts_name, config)
        self.p_type = "SAST"

    def parse_vulnerability(self, raw_vulnerability):
        vulnerability = SastVulnerability(raw_vulnerability)

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
        scanners = list(set(vuln['scanner']['name'] for vuln in vulnerabilities))
        testsuites = []

        for scanner in scanners:
            testcases = []
            relevant_vulns = filter(lambda x: x['scanner']['name'] == scanner, vulnerabilities)
            for vuln in relevant_vulns:
                testcases.append(self.parse_vulnerability(vuln))

            testsuites.append(TestSuite(name=self.ts_name + scanner.replace(' ', '-'), test_cases=testcases))

        # If the report was empty, we generate an empty testsuite to return a valid Junit XML file
        if len(testsuites) == 0:
            testsuites.append(TestSuite(name=self.ts_name, test_cases=[]))
        return testsuites
