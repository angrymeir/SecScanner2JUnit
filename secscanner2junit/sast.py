from collections import defaultdict
from random import randrange

from junit_xml import TestSuite, TestCase

# is it correct import changed from .parser ? I've get error ImportError: attempted relative import with no known parent package
from secscanner2junit.config import Config
from secscanner2junit.parser import Parser


# See following links to learn more about sast scanners and theirs output
# https://docs.gitlab.com/ee/user/application_security/sast/analyzers.html#data-provided-by-analyzers
# https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/sast-report-format.json
class SastParser(Parser):
    def __init__(self, report, ts_name, config: Config):
        super().__init__(report, ts_name, config)
        self.p_type = "SAST"

    def parse_findings(self, finding, time):
        output = ""
        properties = defaultdict(str)
        simple_props = ["id", "name", "message", "description", "severity", "confidence"]
        for prop in simple_props:
            try:
                prop_res = finding[prop]
                properties[prop] = prop_res
                output += "{prop}: {prop_res}\n".format(prop=prop, prop_res=prop_res)
            except KeyError:
                pass

        try:
            url = finding['links'][0]['url']
            properties['url'] = url
            output += "url: {url}\n".format(url=url)
        except (KeyError, IndexError):
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
        
        try:
            output += "identifiers.name: {identifiers_name}\n".format(identifiers_name=finding['identifiers'][0]['name'])
            output += "identifiers.type: {identifiers_type}\n".format(identifiers_type=finding['identifiers'][0]['type'])
            output += "identifiers.value: {identifiers_value}\n".format(identifiers_value=finding['identifiers'][0]['value'])
        except KeyError:
            pass

        f_type = finding['identifiers'][0]['name']
        
        try:
            finding_id = finding['id']
        except KeyError:
            finding_id = str(randrange(1, 10000000))
        
        if properties['name']:
            tc = TestCase(name=properties['name'] + " (ID: " + finding_id + ")", classname=self.p_type, file=properties['file'], elapsed_sec=time, line=properties['start_line'])
        else:
            tc = TestCase(name=f_type + " (ID: " + finding_id + ")", classname=self.p_type, file=properties['file'], elapsed_sec=time, line=properties['start_line'])
        tc.add_failure_info(message=properties['message'], output=output, failure_type=f_type)
        return tc

    def parse(self):
        timing = 0
        findings = self.report['vulnerabilities']
        findings = self.config.suppress(findings)
        scanners = list(set(f['scanner']['name'] for f in findings))
        testsuites = []
        for scanner in scanners:
            rel_find = filter(lambda x: x['scanner']['name'] == scanner, findings)
            testcases = [self.parse_findings(finding, timing) for finding in rel_find]
            testsuites.append(TestSuite(name=self.ts_name + scanner.replace(' ', '-'), test_cases=testcases))
        return testsuites

