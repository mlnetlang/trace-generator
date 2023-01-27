import pickle
import os
import errno

class BinaryReader(object):
    """ A helper for storing objects as file and visa versa
    """
    
    def read(path: str, default = None) -> any:
        try:
            with open(path, 'rb') as inf:
                return pickle.load(inf)
        except:
            return default
    
    def write(data: any, path: str) -> None:
        if not os.path.exists(os.path.dirname(path)):
            try:
                os.makedirs(os.path.dirname(path))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(path, 'wb') as outfile:
            pickle.dump(data, outfile)