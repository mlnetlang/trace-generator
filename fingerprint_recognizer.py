
class FingerprintRecognizer(object):
    """
    """

    def __init__(self, symbols: dict, config: dict = {}):
        self.config = {}
        self.symbols = symbols
        self.config.update(self.default_config)
        self.config.update(config)

    
    def recognize(self, flows):
        pass

    def get_symbols(self) -> dict:
        return self.symbols

