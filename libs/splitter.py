import pickle
from sklearn.model_selection import train_test_split
from typing import List


class Splitter(object):
    """ A helper for splitting data into train/test
    """
    
    def split(data: List, train_size: float) -> any:
        data_train, data_test = train_test_split(
            data, test_size=train_size)
        return dict([('train', data_train), ('test', data_test)])