from .parser import Parser
from junit_xml import TestSuite, TestCase
from collections import defaultdict


class SastParser(Parser):
    def __init__(self, report, ts_name):
        super().__init__(report, ts_name)
        self.p_type = "SAST"

    def parse_findings(self, finding, time):
        output = ""
        properties = defaultdict(str)
        simple_props = ["name", "message", "description", "severity", "confidence"]
        for prop in simple_props:
            try:
                prop_res = finding[prop]
                properties[prop] = prop_res
                output += "{prop}: {prop_res}\n".format(prop=prop, prop_res=prop_res)
            except KeyError:
                pass

        try:
            url = finding['links']['url']
            properties['url'] = url
            output += "url: {url}\n".format(url=url)
        except KeyError:
            pass

        try:
            file = finding['location']['file']
            properties['file'] = file
            output += "file: {file}\n".format(file=file)
        except KeyError:
            pass

        try:
            vclass = finding['location']['class']
            properties['class'] = vclass
            output += "class: {vclass}\n".format(vclass=vclass)
        except KeyError:
            pass

        try:
            method = finding['location']['method']
            properties['method'] = method
            output += "method: {method}\n".format(method=method)
        except KeyError:
            pass

        try:
            start_line = finding['location']['start_line']
            properties['start line'] = start_line
            output += "start line: {start_line}\n".format(start_line=start_line)
        except KeyError:
            pass

        try:
            end_line = finding['location']['end_line']
            properties['end line'] = end_line
            output += "end line: {end_line}\n".format(end_line=end_line)
        except KeyError:
            pass

        f_type = finding['identifiers'][0]['name']
        if properties['name']:
            tc = TestCase(name=properties['name'], classname=self.p_type, file=properties['file'], elapsed_sec=time, line=properties['start_line'])
        else:
            tc = TestCase(name=f_type, classname=self.p_type, file=properties['file'], elapsed_sec=time, line=properties['start_line'])
        tc.add_failure_info(message=properties['message'], output=output, failure_type=f_type)
        return tc

    def parse(self):
        timing = 0
        findings = self.report['vulnerabilities']
        scanners = list(set(f['scanner']['name'] for f in findings))
        testsuites = []
        for scanner in scanners:
            rel_find = filter(lambda x: x['scanner']['name'] == scanner, findings)
            testcases = [self.parse_findings(finding, timing) for finding in rel_find]
            testsuites.append(TestSuite(name=self.ts_name + scanner.replace(' ', '-'), test_cases=testcases))
        return testsuites
