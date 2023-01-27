import numpy as np
from models.flow import Flow
from libs.pcap_reader import PcapReader
import os


def test_read_invalid_path_should_throw_exception():
    # arrange
    sut = PcapReader()
    # act
    try:
        sut.read("")
        assert False
    except Exception as e:
        print(e)
        assert True
    # assert


def test_read_invalid_file_should_return_empty_dictionary():
    # arrange
    sut = PcapReader()

    # act
    dir_path = os.path.dirname(os.path.realpath(__file__))
    res = sut.read(dir_path + "/files_fingerprint_recognizer/invalid_input.pcap")

    # assert
    assert not bool(res)


def test_tshark_should_be_installed():
    # arrange
    sut = PcapReader()
    dir_path = os.path.dirname(os.path.realpath(__file__))

    # act
    try:
        res = sut.read(dir_path + "/files_fingerprint_recognizer/valid_input.pcap")
    except ModuleNotFoundError  as ex:
        assert False
    except:
        assert True


def test_read_should_not_throw_os_exception():
    # arrange
    sut = PcapReader()
    dir_path = os.path.dirname(os.path.realpath(__file__))

    # act
    try:
        res = sut.read(dir_path + "/files_fingerprint_recognizer/valid_input.pcap")
    except OSError as ex:
        assert False
    except:
        assert True


def test_read_valid_file_should_return_dictionary_of_flows():
    # arrange
    sut = PcapReader()

    # act
    dir_path = os.path.dirname(os.path.realpath(__file__))
    res = sut.read(dir_path + "/files_fingerprint_recognizer/valid_input.pcap")

    # assert
    assert all(isinstance(x, Flow) for x in res.values())


def test_read_valid_file_should_return_non_empty_dictionary():
    # arrange
    sut = PcapReader()

    # act
    dir_path = os.path.dirname(os.path.realpath(__file__))
    res = sut.read(dir_path + "/files_fingerprint_recognizer/valid_input.pcap")

    # assert
    assert bool(res)
