#!/usr/bin/env python

import os
import sys

from core import Tool

# make the title
if os.name == "nt":
    import ctypes

    ctypes.windll.kernel32.SetConsoleTitleW("TIK5_Alpha")
else:
    sys.stdout.write("\x1b]2;TIK5_Alpha\x07")
    sys.stdout.flush()


if __name__ == "__main__":
    Tool().main()
