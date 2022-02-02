class Parser:
    def __init__(self, report, ts_name):
        self.report = report
        self.ts_name = ts_name.rsplit('.', 1)[0].replace('.', '_')

    def parse(self):
        pass
