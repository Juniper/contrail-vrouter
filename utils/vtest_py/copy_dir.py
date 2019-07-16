#!/usr/bin/python

import sys
import shutil

def main():
    print "copy dir src:%s dst:%s" %(sys.argv[1], sys.argv[2])
    shutil.rmtree(sys.argv[2], ignore_errors=True)
    shutil.copytree(sys.argv[1], sys.argv[2])
    return 0

if __name__ == "__main__":
    main()

