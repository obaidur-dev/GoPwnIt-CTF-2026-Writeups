#!/usr/bin/env python3
# The file is named .tgz but it is really a RAR5 archive.
# No unrar on my box, so I used libarchive (pip install libarchive-c).
# usage: python3 -I extract.py <archive> <out_dir>
import os
import sys

import libarchive

archive, out_dir = sys.argv[1], sys.argv[2]
os.makedirs(out_dir, exist_ok=True)
with libarchive.file_reader(archive) as a:
    for e in a:
        print(e.pathname, e.size)
        dest = os.path.join(out_dir, os.path.basename(e.pathname))
        with open(dest, "wb") as f:
            for block in e.get_blocks():
                f.write(block)
        os.chmod(dest, 0o755)
