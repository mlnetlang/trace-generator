from typing import Iterable
import os
import errno

class TextReader(object):
    def read(path: str) -> str:
        file = open(path, 'r')
        return file.read()

    def write(data: str, path: str) -> None:
        if not os.path.exists(os.path.dirname(path)):
            try:
                os.makedirs(os.path.dirname(path))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
                
        with open(path, 'w') as file:
            file.write(data)

    def write_lines(data: Iterable[str], path: str) -> None:
        if not os.path.exists(os.path.dirname(path)):
            try:
                os.makedirs(os.path.dirname(path))
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise
        with open(path, 'w') as file:
            file.writelines(data)