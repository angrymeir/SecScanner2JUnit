from datetime import datetime as dt

from junit_xml import TestSuite, TestCase

from .parser import Parser
from .vulnerability import SastVulnerability


class SecretsParser(Parser):
    def __init__(self, report, ts_name, config):
        super().__init__(report, ts_name, config)
        self.p_type = "Secrets"

    def parse_findings(self, finding, time):
        vulnerability = SastVulnerability(finding)
        tc = TestCase(name=vulnerability.get_testcase_name(),
                      classname=self.p_type,
                      file=vulnerability.get_location(),
                      elapsed_sec=time,
                      line=vulnerability.get_start_line())

        tc.add_failure_info(message=vulnerability.get_description(),
                            output=vulnerability.get_output(),
                            failure_type=vulnerability.get_failure_type())
        return tc

    def parse(self):
        version = self.report['scan']['scanner']['version']
        findings = self.report['vulnerabilities']
        findings = self.config.suppress(findings)
        start_time = self.report['scan']['start_time']
        end_time = self.report['scan']['end_time']
        timing = dt.strptime(end_time, '%Y-%m-%dT%H:%M:%S') - dt.strptime(start_time, '%Y-%m-%dT%H:%M:%S')
        testcases = [self.parse_findings(finding, timing.seconds) for finding in findings]
        ts = TestSuite(name=self.ts_name + '-' + version, test_cases=testcases, timestamp=start_time)
        return [ts]
