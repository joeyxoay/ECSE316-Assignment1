import collections
import random
import socket as soct
import struct
import time
import sys

xtimeout = 5
xmaxretries = 3
xport = 53
xRecordT = "A"
xip = ""
xname = ""
q_type = 0x0001


def main(args):
    global xtimeout
    global xmaxretries
    global xport
    global xRecordT
    global xip
    global xname
    global q_type

    #parse input
    i = 0
    while args[i][0] != "@":
        if args[i] == "-t": xtimeout = int(args[i + 1])
        elif args[i] == "-r": xmaxretries = int(args[i + 1])
        elif args[i] == "-p": xport = int(args[i + 1])
        elif args[i] == "-mx":
            xRecordT = "MX"
            q_type = 0x000F
        elif args[i] == "-ns":
            xRecordT = "NS"
            q_type = 0x0002
        
        i = i + 1

    xip = args[i][1:]
    i = i + 1
    xname = args[i]

    print("DnsClient sending request for " + xname)
    print("Server: " + xip)
    print("Request type: " + xRecordT)

    #build packet
    parts = xname.split(".")
    npacket = b""  #create an empty byte object
    randomn = random.getrandbits(16)  #generate 16 bit random number

    #create packet with required sections
    npacket += randomn.to_bytes(2, byteorder="big")
    #flags
    npacket += (256).to_bytes(2, byteorder="big")
    #questions
    npacket += (1).to_bytes(2, byteorder="big")
    #answers
    npacket += (0).to_bytes(2, byteorder="big")
    #authorities
    npacket += (0).to_bytes(2, byteorder="big")
    #additional
    npacket += (0).to_bytes(2, byteorder="big")

    #append the packed values for each part of the URL
    numberOfPartsURL = len(parts)  #2 for google.com
    for i in range(numberOfPartsURL):  #google, com
        npacket += (len(parts[i])).to_bytes(1, byteorder="big")
        for byte in parts[i]:
             #add the bytes in utf encoding
            npacket += byte.encode("utf-8")

    #append the packed value for the end of the string
    #mark end
    npacket += (0).to_bytes(1, byteorder="big")
    #type
    npacket += q_type.to_bytes(2, byteorder="big")
    #class, set 1 as per PDF
    npacket += (0x0001).to_bytes(2, byteorder="big")

    #build socket
    socket = soct.socket(soct.AF_INET, soct.SOCK_DGRAM)
    socket.settimeout(xtimeout)
    socket.setsockopt(soct.SOL_SOCKET, soct.SO_REUSEADDR, 1)
    socket.bind(("", xport))

    #send request
    tempi = 0
    for tempi in range(xmaxretries):
        try:
            timeO = time.time()
            socket.sendto(npacket, (xip, xport))
            data = socket.recvfrom(512)[0]
            timeA = time.time()
            socket.close()
            print(
                "Response received after "
                + str(timeA - timeO)[:5] #pretty format the number
                + " seconds ("
                + str(tempi)
                + " retries)"
            )
            break
        except soct.timeout:
            print("ERROR\tSocket timeout")
            print("ERROR\tAttemping connection again...")
        except Exception as e:
            print("ERROR\t" + str(e))
    if tempi == xmaxretries - 1:
        print("ERROR\tMaximum number of retries " + str(xmaxretries) + " exceeded")
        return
    unpackedStruck = struct.Struct("!HHHHHH").unpack_from(data)

    flags = unpackedStruck[1]
    numAnswers = unpackedStruck[3]
    arcount = unpackedStruck[5]

    #we start offset after the Header section
    offset96bits = struct.Struct("!HHHHHH").size

    isAuthority = (128 & flags) != 0
    offset_decode = decompress(data, offset96bits)[1] + struct.Struct("!HH").size

    #answer section
    authstring = "auth" if (not isAuthority) else "nonauth"
    answersz = []
    additionalz = []
    lastoffset = offset_decode
    for i in range(numAnswers):
        answers, offsetz = print_line(data, lastoffset, authstring)
        answersz.append(answers)
        lastoffset = offsetz
    for i in range(arcount):
        additional, offsetz = print_line(data, lastoffset, authstring)
        additionalz.append(additional)
        lastoffset = offsetz
    if arcount + numAnswers <= 0: print("NOTFOUND")
    if numAnswers > 0:
        print("***Answer Section (" + str(numAnswers) + " records)***")
        for i in range(len(answersz)): print(answersz[i])
    if arcount > 0:
        print("***Additional Section (" + str(arcount) + " records)***")
        for i in range(len(additionalz)): print(additionalz[i])

#prints a line of the answer section
def print_line(data, offset, authString):
    offset = decompress(data, offset)[1]
    type, _, seconds, _ = struct.unpack_from("!2HIH", data, offset)
    offset += struct.calcsize("!2HIH")
    if type == 1:
        ip = ".".join(str(i) for i in struct.unpack_from("!BBBB", data, offset))
        offset += struct.calcsize("!BBBB")
        return str(f"IP\t{ip}\t{seconds}\t{authString}"), offset
    elif type == 2:
        name, offset = decompress(data, offset)
        return str(f"NS\t{deepFlatten(name)}\t{seconds}\t{authString}"), offset
    elif type == 5:
        name, offset = decompress(data, offset)
        return str(f"CNAME\t{deepFlatten(name)}\t{seconds}\t{authString}"), offset
    elif type == 15:
        (preference,) = struct.unpack_from("!H", data, offset)
        offset += struct.calcsize("!H")
        (exchange,) = decompress(data, offset)
        return f"MX\t{exchange}\t{preference}\t{seconds}\t{authString}", offset
    
    print("ERROR\tRequest type is incorrect")

#converts element, lists or combination to a decoded list of elements
def deepFlatten(input):
    result = []
    if isinstance(input, list):
        for element in input:
            if isinstance(element, list):
                for elementIN in element:
                    result.append(elementIN)
            elif not isinstance(element, int):
                result.append(element)
    else: result = [input]

    flattened = b".".join(result)
    flattened = flattened.decode()
    return flattened

#follows the PDF's explanation about packet compression
def decompress(input, offset):
    result = []
    currbyte = struct.unpack_from("!B", input, offset)[0]
    #repeat until end byte found or reading pointer line
    while currbyte != 0xC0:
        if currbyte == 0x00: return result,(offset + 1)
        tempunpack = struct.unpack_from("!%ds" % currbyte, input, (offset + 1))
        result.append(*tempunpack)
        offset += currbyte + 1
        currbyte = struct.unpack_from("!B", input, (offset))[0]

    fullline = struct.unpack_from("!H", input, offset)[0]
    return (list(result) + list(decompress(input, fullline & 0x3FFF))), (offset + 2)

if __name__ == "__main__":
    main(sys.argv[1:])