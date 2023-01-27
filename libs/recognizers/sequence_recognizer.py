
from typing import List
from fingerprint_recognizer import FingerprintRecognizer
from models.flow import Flow
import math

class SequenceRecognizer(FingerprintRecognizer):

    def __init__(self, symbols: dict, config: dict = {}):
        self.default_config = {
            "flow_duration":0,
            "session_threshold": 0.5
        }
        super().__init__(symbols, config=config)
    
    def recognize(self, flows):
        """Starts recognizing flows and generating symbols sequence for each app
        """
        return self.generate_symbols_sequence(flows)

    def generate_symbols_sequence(self, flows: List[Flow]):
        """Generates sequence of symbols frow list of flows

        Args:
            flows (List[Flow]): given list of flow objects

        Returns:
            List[str]: Sequence of strings. Each string represents a symbol
        """
        symbols_last_captured_timestamps = {}
        symbols_sequence = []

        # Sort flows of each app by time_start
        # It's already sorted, just in case
        sorted_flows = sorted(flows, key=lambda k: k.time_start)
        if(len(sorted_flows) > 0):
            last_all_captured_timestamp = sorted_flows[0].time_start

        # Loop through all flows of the app
        for flow in sorted_flows:

            # get related symbol representing the flow
            symbol = self.get_or_assign_flow_symbol(flow)

            # If the symbol is not already captured in the defined time range then capture it in symbol sequence
            last_timestamp = symbols_last_captured_timestamps.get(symbol,-math.inf)
        
            if flow.time_start - last_timestamp > self.config["flow_duration"]:
                if flow.time_start - last_all_captured_timestamp > self.config["session_threshold"]:
                    symbols_sequence.append('|')
                symbols_sequence.append(symbol)
                symbols_last_captured_timestamps[symbol] = flow.time_start
                last_all_captured_timestamp = flow.time_start
        return symbols_sequence

    def get_or_assign_flow_symbol(self, flow: Flow):
        """Returns an already assigned symbol for the flow.
        Or generates and assign a new symbol to the flow if not exists

        Args:
            flow (Flow): The flow which we want to find a symbol for

        Returns:
            str: A string representing symbol to specific flow
        """
        if not flow.destination in self.symbols:
            self.symbols[flow.destination] = "S" + str(len(self.symbols) + 1)

        return self.symbols.get(flow.destination)
        