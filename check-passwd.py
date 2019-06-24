# check-passwd.py
#
# script to check for a particular password (as a sha1) in the passwords
#  database

import getpass
import hashlib
import os

def StrGetPass():
    """Prompt (silently, no echo) for a password and return the string"""

    return getpass.getpass("Password to check for:")

def StrSha1(strIn):
    """Compute and return (as a string, hexdigest) the sha1 of the given input"""

    sha1 = hashlib.sha1()
    sha1.update(strIn)
    return sha1.hexdigest()

def CInstanceFind(strSha1):
    """Return the instance count for the given sha1 in the password database"""

    s_path = 'pwned-passwords-sha1-ordered-by-hash-v4.txt'
    statres = os.stat(s_path)
    print("size: {} bytes".format(statres.st_size))

    with open(s_path, 'rb') as fileIn:

        iMic = 0
        iMac = statres.st_size
        iMicPrev = -1
        iMacPrev = -1

        while iMic < iMac and (iMicPrev != iMic or iMacPrev != iMac):
            # extract data from the midpoint of the file

            iMicPrev = iMic
            iMacPrev = iMac

            iMid = (iMac + iMic) / 2
            fileIn.seek(iMid)
            strMid = fileIn.read(256)

            # DEBUG
            print("Scanning at {} {} {} -> {}".format(iMic, iMid, iMac, repr(strMid)[:50]))

            # determine the first hash location (newline-separated)

            lPart = strMid.split('\n')
            iPart = 0
            while iPart < 1:
                lSub = lPart[iPart].split(':')
                if len(lSub) != 2:
                    # invalid first entry -- no colon delimiter
                    iPart += 1
                    continue
                elif len(lSub[0]) != 40:
                    # invalid first entry -- no full hash
                    iPart += 1
                    continue
                break

            # compare the hash to our input

            strSha1Mid, strInstance = lPart[iPart].split(':')
            n = cmp(strSha1.lower(), strSha1Mid.lower())

            if n == 0:
                # found exact match, return number
                return int(strInstance.strip())

            elif n == -1:
                # input hash before mid hash, so scan earlier data

                iMac = iMid
                if iPart > 0:
                    iMac += len(lPart[iPart])
            else:
                # input hash after mid hash, so scan later data

                iMic = iMid + len(lPart[iPart])
                if iPart > 0:
                    iMic += len(lPart[0])
            
    # hash wasn't found

    return 0

if __name__ == '__main__':
    while True:
        strPass = StrGetPass()
        # don't normally do this!
        #print "Password: {}".format(repr(strPass))
        strSha1 = StrSha1(strPass)
        print "Scanning for sha1 {}".format(strSha1)
        cInstance = CInstanceFind(strSha1)
        print "Instances: {}".format(cInstance)
