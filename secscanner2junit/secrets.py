from datetime import datetime as dt

from junit_xml import TestSuite, TestCase

from .parser import Parser


class SecretsParser(Parser):
    def __init__(self, report, ts_name, config):
        super().__init__(report, ts_name, config)
        self.p_type = "Secrets"

    def parse_findings(self, finding, time):
        name = finding['name']
        message = finding['message']
        location_file = finding['location']['file']
        location_line = finding['location']['start_line']
        tc = TestCase(name=name, classname=self.p_type, file=location_file, elapsed_sec=time, line=location_line)
        tc.add_failure_info(message=message, output=message)
        return tc

    def parse(self):
        version = self.report['scan']['scanner']['version']
        findings = self.report['vulnerabilities']
        start_time = self.report['scan']['start_time']
        end_time = self.report['scan']['end_time']
        timing = dt.strptime(end_time, '%Y-%m-%dT%H:%M:%S') - dt.strptime(start_time, '%Y-%m-%dT%H:%M:%S')
        testcases = [self.parse_findings(finding, timing.seconds) for finding in findings]
        ts = TestSuite(name=self.ts_name + '-' + version, test_cases=testcases, timestamp=start_time)
        return [ts]
