import hashlib
import sys
import argparse

algorithms = ["MD5", "SHA1", "SHA256", "SHA224", "SHA384", "SHA512"]

def hashed(binarys, hashed=None):
    for algorithm in algorithms:
        if hashed == None:
            if algorithm == "MD5":
                print("MD5: %s"%(hashlib.md5(binarys).hexdigest()))
            elif algorithms == "SHA1":
                print("SHA1: %s"%(hashlib.sha1(binarys).hexdigest()))
            elif algorithm == "SHA256":
                print("SHA256: %s"%(hashlib.sha256(binarys).hexdigest()))
            elif algorithm == "SHA224":
                print("SHA224: %s"%(hashlib.sha224(binarys).hexdigest()))
            elif algorithm == "SHA384":
                print("SHA384: %s"%(hashlib.sha384(binarys).hexdigest()))
            elif algorithm == "SHA512":
                print("SHA512: %s"%(hashlib.sha512(binarys).hexdigest()))
                return 0

        elif hashed != None:
            if algorithm == "MD5":
                if hashed == str(hashlib.md5(binarys).hexdigest()):
                    print("\033[1;36m[+]Matched MD5: %s \033[1;m"%(hashlib.md5(binarys).hexdigest()))
                    return 0
            elif algorithms == "SHA1":
                if hashed == hashlib.sha1(binarys).hexdigest():
                    print("\033[1;36m[+]Matched SHA1: %s \033[1;m"%(hashlib.sha1(binarys).hexdigest()))
                    return 0
            elif algorithm == "SHA256":
                if hashed == hashlib.sha256(binarys).hexdigest():
                    print("\033[1;36m[+]Matched SHA256: %s \033[1;m"%(hashlib.sha256(binarys).hexdigest()))
                    return 0
            elif algorithm == "SHA224":
                if hashed == hashlib.sha224(binarys).hexdigest():
                    print("\033[1;36m[+]Matched sha224: %s \033[1;m"%(hashlib.sha224(binarys).hexdigest()))
                    return 0
            elif algorithm == "SHA384":
                if hashed == hashlib.sha384(binarys).hexdigest():
                    print("\033[1;36m[+]Matched SHA384: %s \033[1;m"%(hashlib.sha384(binarys).hexdigest()))
                    return 0
            elif algorithm == "SHA512":
                if hashed == hashlib.sha512(binarys).hexdigest():
                    print("\033[1;36m[+]Matched SHA512: %s \033[1;m"%(hashlib.sha512(binarys).hexdigest()))
                    return 0
    
    print("\033[1;33m[-]MD5, SHA1, SHA256, SHA224, SHA384, SHA512 Not Matched \033[1;m")
    return 1

def readbinary(filname):
    opnr = open(filname, "rb")
    return opnr.read()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Options")
    parser.add_argument("--hashfile", type=str, help="Enter You're File Path")
    parser.add_argument("--match", type=str, help="Enter You're Expected Passwords")
    args = parser.parse_args()    
    if args.match != None:
        hashed(readbinary(args.hashfile), args.match)
        sys.exit()
    elif args.hashfile != None:
        hashed(readbinary(args.hashfile))