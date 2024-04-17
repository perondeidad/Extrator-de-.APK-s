#!/usr/bin/env python3
from collections import namedtuple
import io
import os
import struct
from typing import Dict, List


APKHeader = namedtuple("APKHeader", ["id", "files_offset", "file_count", "dir_offset"])


class APKEntry:
    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.path} @ 0x{self.data_offset:016X}>"

    @classmethod
    def from_stream(cls, apk_file) -> int:
        out = cls()
        path_len = int.from_bytes(apk_file.read(4), "little")
        path = apk_file.read(path_len + 1).decode()
        assert len(path) == path_len + 1, "path string ends prematurely"
        assert path[-1] == "\0", "path string is not zero terminated"
        out.path = path[:-1].replace("\\", "/")
        out.data_offset, out.data_size, out.next_entry_offset, out.unknown = struct.unpack("4I", apk_file.read(16))
        return out


class APKFile:
    _file: io.BufferedReader
    files: Dict[str, APKEntry]

    def __init__(self, apk_filename: str):
        self._file = open(apk_filename, "rb")
        self.files = dict()
        header = APKHeader(*struct.unpack("4s3I", self._file.read(16)))
        assert header.id == b"\x57\x23\x00\x00", "not a valid .apk file"
        self._file.seek(header.dir_offset)
        for i in range(header.file_count):
            entry = APKEntry.from_stream(self._file)
            self.files[entry.path] = entry
            self._file.seek(entry.next_entry_offset)

    def __del__(self):
        self._file.close()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self._file.name}>"

    def namelist(self) -> List[str]:
        return sorted(self.files.keys())

    def extract(self, filename: str, dest_filename: str = None):
        assert filename in self.files, "file not found"
        entry = self.files[filename]
        self._file.seek(entry.data_offset)
        dest = filename if dest_filename is None else dest_filename
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as out_file:
            out_file.write(self._file.read(entry.data_size))

    def extractall(self, dest_folder: str = "./"):
        for filename in self.files:
            self.extract(filename, os.path.join(dest_folder, filename))


if __name__ == "__main__":  # drag & drop behaviour
    import sys

    def main():
        if len(sys.argv) == 1:
            print("usage: apk.py FILES...")
            print("\textracts contents of each .apk file given")
            return
        for apk_filename in sys.argv[1:]:
            APKFile(apk_filename).extractall()

    main()