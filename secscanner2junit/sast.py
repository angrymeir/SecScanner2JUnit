from .parser import Parser
from junit_xml import TestSuite, TestCase


class SastParser(Parser):
    def __init__(self, report, ts_name):
        super().__init__(report, ts_name)
        self.p_type = "SAST"

    def parse_findings(self, finding, time):
        name = finding['message']
        message = finding['message']
        location_file = finding['location']['file']
        location_line = finding['location']['start_line']
        url = finding['identifiers'][0]['url']
        f_type = finding['identifiers'][0]['name']
        tc = TestCase(name=name, classname=self.p_type, file=location_file, elapsed_sec=time, line=location_line)
        tc.add_failure_info(message=message, output=url, failure_type=f_type)
        return tc

    def parse(self):
        timing = 0
        findings = self.report['vulnerabilities']
        scanners = [f['scanner']['name'] for f in findings]
        testsuites = []
        for scanner in scanners:
            rel_find = filter(lambda x: x['scanner']['name'] == scanner, findings)
            testcases = [self.parse_findings(finding, timing) for finding in rel_find]
            testsuites.append(TestSuite(name=self.ts_name + scanner.replace(' ', '-'), test_cases=testcases))
        return testsuites
