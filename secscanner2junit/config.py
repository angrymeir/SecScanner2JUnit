from collections import namedtuple

from yaml import safe_load


class Suppression:
    def __init__(self, type, value):
        self.type = type
        self.value = value

    def __repr__(self):
        return f"Suppression(type={self.type}, value={self.value})"


class Config:
    def __init__(self, suppressions: list[Suppression]):
        self.suppressions = suppressions

    def __repr__(self):
        return f"Config(suppressions={self.suppressions})"

    def suppress(self, findings):
        output = []
        for finding in findings:
            for identifier in finding['identifiers']:
                if self.suppressions == "TODO":
                    pass


def get_config(path):
    try:
        with open(path) as f:
            yml_dict = safe_load(f)

            suppressions = []
            for suppression in yml_dict['sast']['suppressions']:
                suppressions.append(namedtuple("Suppression", suppression.keys())(*suppression.values()))

            config = Config(suppressions)

            print("Loaded config:")
            print(config)

            return config
    except FileNotFoundError:
        print("No config found at path: " + path)
        return Config([])
