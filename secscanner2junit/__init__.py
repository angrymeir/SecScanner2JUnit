import sys
import enum
import json
from junit_xml import to_xml_report_file
from .secrets import SecretsParser
from .sast import SastParser


class ScanType(enum.Enum):
    SECRETS = 'secrets'
    SAST = 'sast'


def load(input_path):
    with open(input_path) as input_file:
        report = json.load(input_file)
    return report


def save_junit_report(testsuite, output_path):
    with open(output_path, 'w') as output_file:
        to_xml_report_file(output_file, testsuite, prettyprint=True)


def main():
    scan_type, input_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3]
    report = load(input_path)
    if scan_type == ScanType.SECRETS.value:
        parser = SecretsParser(report, input_path)
    elif scan_type == ScanType.SAST.value:
        parser = SastParser(report, input_path)
    else:
        raise NotImplementedError
    testsuite = parser.parse()
    save_junit_report(testsuite, output_path)


if __name__ == '__main__':
    main()
