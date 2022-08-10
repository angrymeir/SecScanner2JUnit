class Parser:
    def __init__(self, report, ts_name, config):
        self.report = report
        self.ts_name = ts_name.rsplit('.', 1)[0].replace('.', '_')
        self.config = config

    def parse(self):
        pass
