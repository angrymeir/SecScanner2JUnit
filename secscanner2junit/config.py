from yaml import safe_load


class Suppression:
    def __init__(self, type, value):
        self.type = type
        self.value = value

    def __repr__(self):
        return f"Suppression(type={self.type}, value={self.value})"

    def __eq__(self, other):
        if isinstance(other, Suppression):
            return self.type == other.type and self.value == other.value

        return False


class Config:
    def __init__(self, suppressions: list[Suppression]):
        self.suppressions = suppressions

    def __repr__(self):
        return f"Config(suppressions={self.suppressions})"

    def __eq__(self, other):
        if isinstance(other, Config):
            return self.suppressions == other.suppressions

        return False

    def __is_identifier_suppressed(self, identifier):
        for suppression in self.suppressions:
            if suppression.type == identifier['type'] and suppression.value == identifier['value']:
                return True
        return False

    def __is_vulnerability_suppressed(self, vulnerability):
        for identifier in vulnerability['identifiers']:
            if self.__is_identifier_suppressed(identifier):
                return True
        return False

    def suppress(self, vulnerabilities):
        output = list()
        for vulnerability in vulnerabilities:
            if self.__is_vulnerability_suppressed(vulnerability):
                print("Ignoring: " + str(vulnerability))
            else:
                output.append(vulnerability)

        return output


def get_config(path):
    try:
        with open(path) as f:
            yml_dict = safe_load(f)

            suppressions = []
            config_yml = __get_yml_config(yml_dict)
            for suppression in __get_suppressions(config_yml):
                suppressions.append(__get_suppression(suppression))

            config = Config(suppressions)

            print("Loaded config:")
            print(config)

            return config
    except FileNotFoundError as e:
        print("No config found at path: " + path)
        return Config([])


def __get_yml_config(config_yml_dict):
    try:
        return config_yml_dict['sast']
    except TypeError:
        return dict()
    except KeyError:
        return dict()


def __get_suppressions(sast_yml_dict):
    try:
        return sast_yml_dict['suppressions']
    except KeyError:
        return list()


def __get_suppression(suppression_yml_dict):
    try:
        return Suppression(suppression_yml_dict['type'], suppression_yml_dict['value'])
    except KeyError:
        return None
