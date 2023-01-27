import argparse
from libs.splitter import Splitter
from libs.recognizers.sequence_recognizer import SequenceRecognizer
from libs.text_reader import TextReader
from libs.pcap_reader import PcapReader
from libs.binary_reader import BinaryReader
from fingerprint_recognizer import FingerprintRecognizer
from pathlib import Path

import nest_asyncio
nest_asyncio.apply()



def run(pcaps_paths=[], flows_paths=[], write_flows_dir='', symbols_path='', out_dir='', train_size=0.0, recognizer=None):
    # Phase 1: Read flows from pcap file or binary file
    flows_per_app = dict()
    if flows_paths:
        for flow_path in flows_paths:
            appName = Path(flow_path).parts[-1]
            # appName = Path(flow_path).stem
            
            executionName = Path(flow_path).stem
            flows_per_app[appName] = flows_per_app.get(appName, {'all': {}})
            print(f"reading binaries from {flow_path}")
            flows_per_app[appName]['all'][executionName] = BinaryReader.read(flow_path)

            if write_flows_dir:
                write_path = write_flows_dir + '/' + appName + '/' + executionName + '.p'
                print(f"writing binaries into {write_path}")
                BinaryReader.write(flows_per_app[appName]['all'][executionName], write_path)

    elif pcaps_paths:
        pcap_reader = PcapReader()
        for pcaps_path in pcaps_paths:
            appName = Path(pcaps_path).parts[-2]
            executionName = Path(pcaps_path).stem
            flows_per_app[appName] = flows_per_app.get(appName, {'all': {}})
            print(f"reading pcaps from {pcaps_path}")

            flows_per_app[appName]['all'][executionName] = pcap_reader.read(pcaps_path)

            if write_flows_dir:
                write_path = write_flows_dir + '/' + appName + '/' + executionName + '.p'
                print(f"writing binaries into {write_path}")
                BinaryReader.write(flows_per_app[appName]['all'][executionName], write_path)
                
    else:
        raise Exception("There is no input file specified")

    # Phase 2: Save flows as binary if output path is speficied


    # Phase 3: Load previously saved symbols dictionary
    symbols = {}
    if symbols_path:
        symbols = BinaryReader.read(symbols_path, {})


    # Phase 4: Split test/train data if needed
    reshape_flows_per_app(flows_per_app, train_size)


    # Phase 5: Generate sequence of symbols based on symbols set and flows

    fingerprint_recognizer = build_recognizer(symbols, recognizer)

    for appName, value in flows_per_app.items():
        result = {}
        for label, v in value.items():
            result[label] = []
            for executionName, flows in v.items():
                # IT IS THE MAIN PART OF APPLICATION
                r = fingerprint_recognizer.recognize(flows)
                result[label].append(r)

        # Phase 6: Save generated sequence of symbols
        if out_dir:
            save_app_flows(appName, result, out_dir);        
        
        # Phase 7: Save set of unique symbols to use in the future
        if symbols_path:
            symbols = fingerprint_recognizer.get_symbols()
            BinaryReader.write(symbols, symbols_path)


def save_app_flows(appName, result, out_dir):
    for label, symbols in result.items():
        TextReader.write_lines([" ".join(r) + "\n" for r in symbols], out_dir + '/' + appName + '_' + label + '.txt')


def reshape_flows_per_app(flows_per_app, train_size):

    for key, value in flows_per_app.items():
        for executionName,flows in value['all'].items():
            value['all'][executionName] = list(flows.values())

    if(train_size > 0):
        for key, value in flows_per_app.items():
            data = {}
            for executionName,flows in value['all'].items():
                data = Splitter.split(flows, train_size)
                flows_per_app[key]['train'] = flows_per_app[key].get('train', {})
                flows_per_app[key]['test'] = flows_per_app[key].get('test', {})
                flows_per_app[key]['train'][executionName] = data['train']
                flows_per_app[key]['test'][executionName] = data['test']

def build_recognizer(symbols_set, recognizer):
    if(recognizer == 'SequenceRecognizer'):
        return SequenceRecognizer(symbols_set)
    else:
        return SequenceRecognizer(symbols_set)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="""FingerprintRecognizer: 
        Fingerprint recognition of applications on the network environment by integrating machine and automata learning methods"""
    )

    # Flow data input/output agruments
    group_data_in = parser.add_argument_group("Flow data input/output")
    group_data_in.add_argument('-rp', '--pcaps_paths', type=str, nargs='+')
    group_data_in.add_argument('-rf', '--flows_paths', type=str, nargs='+')
    group_data_in.add_argument('-wf', '--write_flows_dir', type=str)
    group_data_in.add_argument('-symbols', '--symbols_path', type=str)
    group_data_in.add_argument('-o', '--out_dir', type=str)
    group_data_in.add_argument('-r', '--recognizer', type=str)
    group_data_in.add_argument('-train', '--train_size', type=float,default=0)



    args = parser.parse_args()
    run(**vars(args))
