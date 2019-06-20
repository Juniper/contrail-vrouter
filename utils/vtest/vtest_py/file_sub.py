#!/usr/bin/python

import sys
import re
import shutil

# do 'sed like' string substitution in file
def sub_string_in_file(infile, search_str, sub_str, outfile):
    print "doing substitution"
    fhr = open(infile, "r")
    fhw = open(outfile, "w")
    while (1):
        line = fhr.readline()
        if (line != ""):
            pattern = re.compile(search_str)
            wline = pattern.sub(sub_str, line)
            fhw.write(wline)
        else:
            break
    fhr.close()
    fhw.close()
    return 0

def main():
    print "file_sub %s" %(sys.argv[1])
    sub_string_in_file(sys.argv[1], "buffer sandesh", "struct", sys.argv[1]+".tmp")
    shutil.move(sys.argv[1]+".tmp", sys.argv[1])
    return 0

if __name__ == "__main__":
    main()

