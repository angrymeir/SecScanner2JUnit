import enum
import json
import sys
import argparse
from junit_xml import to_xml_report_file

VERSION = "1.0.1"

from secscanner2junit.config import get_config, Config
from secscanner2junit.container_scanning import ContainerScanningParser
from secscanner2junit.maven_dependency_check import MavenDependencyCheckParser
from secscanner2junit.sast import SastParser
from secscanner2junit.secrets import SecretsParser


class ScanType(enum.Enum):
    SECRETS = 'secrets'
    SAST = 'sast'
    CS = 'container_scanning'
    MAVEN_DEPENDENCY_CHECK = 'maven_dependency_check'


    @staticmethod
    def list():
        return list(map(lambda x: x.value, ScanType))


def load_report(input_path):
    with open(input_path) as input_file:
        report = json.load(input_file)
    return report


def save_junit_report(testsuite, output_path):
    with open(output_path, 'w') as output_file:
        to_xml_report_file(output_file, testsuite, prettyprint=True)


def parse_arguments(args):
    arg_parser = argparse.ArgumentParser(description="SecScanner2JUnit: Convert security scanner output to JUnit format.")
    arg_parser.add_argument('--version', action='version', version=VERSION)
    arg_parser.add_argument('activity', choices=ScanType.list())
    arg_parser.add_argument('input_file')
    arg_parser.add_argument('output_file')
    arg_parser.add_argument('config', nargs='?')
    return arg_parser.parse_args(args)


def main(args=None):

    print("----------------------------------------------------------------------")
    print("-------- Hello! Project maintained by logchange organisation  --------")
    print("--------             Visit: https://logchange.dev             --------")
    print("----------------------------------------------------------------------")

    if args is None:
        args = parse_arguments(sys.argv[1:])
    if args.config:
        ss2ju_config = get_config(args.config)
    else:
        ss2ju_config = Config([])

    report = load_report(args.input_file)
    if args.activity == ScanType.SECRETS.value:
        parser = SecretsParser(report, args.input_file, ss2ju_config)
    elif args.activity == ScanType.SAST.value:
        parser = SastParser(report, args.input_file, ss2ju_config)
    elif args.activity == ScanType.CS.value:
        parser = ContainerScanningParser(report, args.input_file, ss2ju_config)
    elif args.activity == ScanType.MAVEN_DEPENDENCY_CHECK.value:
        parser = MavenDependencyCheckParser(report, args.input_file, ss2ju_config)
    else:
        raise NotImplementedError
    testsuite = parser.parse()
    save_junit_report(testsuite, args.output_file)

    print("----------------------------------------------------------------------")
    print("-------- Hello! Project maintained by logchange organisation  --------")
    print("--------             Visit: https://logchange.dev             --------")
    print("----------------------------------------------------------------------")


if __name__ == '__main__':
    main()
