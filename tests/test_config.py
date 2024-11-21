import unittest

from secscanner2junit.config import get_config, Config, Suppression


class TestConfig(unittest.TestCase):

    def test_get_config_no_file(self):
        # given:
        input_config_path = "resources/test_config/test_get_config_no_file/ss2ju-config.yml"

        # when:
        config = get_config(input_config_path)

        # then:
        expected = Config([])
        self.assertEqual(expected, config)

    def test_get_config_empty_file(self):
        # given:
        input_config_path = "resources/test_config/test_get_config_empty_file/ss2ju-config.yml"

        # when:
        config = get_config(input_config_path)

        # then:
        expected = Config([])
        self.assertEqual(expected, config)

    def test_get_config(self):
        # given:
        input_config_path = "resources/test_config/test_get_config/ss2ju-config.yml"

        # when:
        config = get_config(input_config_path)

        # then:
        expected = Config(
            [Suppression(type='cwe', value='2555'), Suppression(type='find_sec_bugs_type', value='SPRING_ENDPOINT')])
        self.assertEqual(expected, config)
