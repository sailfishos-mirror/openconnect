#!/usr/bin/env python3

import os

def main():
    """
    Reply "success" when we receive "hostchecker".
    """
    io = os.fdopen(0, "r+b", buffering=0)
    started = False
    for line in io:
        line = line.decode("ascii").rstrip()
        if line == "start":
            started = True
        if started and line == "Cookie=hostchecker":
            io.write("200\n3\nsuccess\n\n\n".encode("ascii"))
            started = False

if __name__ == "__main__":
    main()
