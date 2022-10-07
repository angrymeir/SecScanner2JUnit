import enum
import json
import sys

from junit_xml import to_xml_report_file

from secscanner2junit.config import get_config, Config
from secscanner2junit.container_scanning import ContainerScanningParser
from .sast import SastParser
from .secrets import SecretsParser


class ScanType(enum.Enum):
    SECRETS = 'secrets'
    SAST = 'sast'
    CS = 'container_scanning'


def load_report(input_path):
    with open(input_path) as input_file:
        report = json.load(input_file)
    return report


def save_junit_report(testsuite, output_path):
    with open(output_path, 'w') as output_file:
        to_xml_report_file(output_file, testsuite, prettyprint=True)


def load_config():
    if len(sys.argv) >= 5:
        config_path = sys.argv[4]
        return get_config(config_path)
    return Config([])


def main():
    scan_type, input_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3]
    ss2ju_config = load_config()
    report = load_report(input_path)
    if scan_type == ScanType.SECRETS.value:
        parser = SecretsParser(report, input_path, ss2ju_config)
    elif scan_type == ScanType.SAST.value:
        parser = SastParser(report, input_path, ss2ju_config)
    elif scan_type == ScanType.CS.value:
        parser = ContainerScanningParser(report, input_path, ss2ju_config)
    else:
        raise NotImplementedError
    testsuite = parser.parse()
    save_junit_report(testsuite, output_path)


if __name__ == '__main__':
    main()
