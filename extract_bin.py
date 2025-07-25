#! /usr/bin/python3
import json
import gzip
import sys
import os
from pathlib import Path

def get_offset(data: bytes, index: slice):
    return int.from_bytes(data[index], byteorder='little') * 8

def main(args):
    if len(args) < 1 or (not os.path.exists(args[0])):
        print("Usage: python3 extract_bin.py [bin file]")
        return

    bin_path = Path(args[0])
    with open(bin_path, 'rb') as f:
        data = f.read()

    oem_offset = get_offset(data, slice(17, 19))
    psr_offset = get_offset(data, slice(19, 21))
    csr_offset = get_offset(data, slice(21, 23))
    sig_offset = get_offset(data, slice(23, 25))

    basename = bin_path.stem
    out_dir = bin_path.parent
    if oem_offset:
        next_offset = psr_offset if psr_offset else csr_offset
        with open(out_dir.joinpath(f"{basename}_OEM.bin"), 'wb') as fp:
            fp.write(data[oem_offset:next_offset])

    if psr_offset:
        next_offset = csr_offset if csr_offset else sig_offset
        psr_str = gzip.decompress(data[(psr_offset + 56):next_offset]).decode()
        with open(out_dir.joinpath(f"{basename}_PSR.sr"), 'w') as fp:
            json.dump(json.loads(psr_str), fp, indent=4)

    if csr_offset:
        csr_str = gzip.decompress(data[(csr_offset + 56):sig_offset]).decode()
        print(basename)
        with open(out_dir.joinpath(f"{basename}_CSR.sr"), 'w') as fp:
            json.dump(json.loads(csr_str), fp, indent=4)
    
    if sig_offset:
        with open(out_dir.joinpath(f"{basename}_SIG.bin"), 'wb') as fp:
            fp.write(data[sig_offset:])


if __name__ == "__main__":
    main(sys.argv[1:])
