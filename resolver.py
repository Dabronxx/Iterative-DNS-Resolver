#By Branko Andrews, Calvin Ferraro
import sys
import socket
import random
from struct import *

def stringToNetwork(orig_string):
    """
    Converts a standard string to a string that can be sent over
    the network.

    Args:
        orig_string (string): the string to convert

    Returns:
        bytes: The network formatted string (as bytes)

    Example:
        stringToNetwork('www.sandiego.edu.edu') will return
          (3)www(8)sandiego(3)edu(0)
    """
    ls = orig_string.split('.')
    toReturn = b""
    for item in ls:
        formatString = "B"
        formatString += str(len(item))
        formatString += "s"
        toReturn += pack(formatString, len(item), item.encode())
    toReturn += pack("B", 0)
    return toReturn


def networkToString(response, start):
    """
    Converts a network response string into a human readable string.

    Args:
        response (string): the entire network response message
        start (int): the location within the message where the network string
            starts.

    Returns:
        A (string, int) tuple
            - string: The human readable string.
            - int: The index one past the end of the string, i.e. the starting
              index of the value immediately after the string.

    Example:  networkToString('(3)www(8)sandiego(3)edu(0)', 0) would return
              ('www.sandiego.edu', 18)
    """

    toReturn = ""
    position = start
    length = -1
    while True:
        length = unpack("!B", response[position:position+1])[0]
        if length == 0:
            position += 1
            break

        # Handle DNS pointers (!!)
        elif (length & 1 << 7) and (length & 1 << 6):
            b2 = unpack("!B", response[position+1:position+2])[0]
            offset = 0
            for i in range(6) :
                offset += (length & 1 << i) << 8
            for i in range(8):
                offset += (b2 & 1 << i)
            dereferenced = networkToString(response, offset)[0]
            return toReturn + dereferenced, position + 2

        formatString = str(length) + "s"
        position += 1
        toReturn += unpack(formatString, response[position:position+length])[0].decode()
        toReturn += "."
        position += length
    return toReturn[:-1], position
    

def constructQuery(ID, hostname, isMX):
    """
    Constructs a DNS query message for a given hostname and ID.

    Args:
        ID (int): ID # for the message
        hostname (string): What we're asking for

    Returns: 
        string: "Packed" string containing a valid DNS query message
    """
    flags = 0 # 0 implies basic iterative query

    # one question, no answers for basic query
    num_questions = 1
    num_answers = 0
    num_auth = 0
    num_other = 0

    # "!HHHHHH" means pack 6 Half integers (i.e. 16-bit values) into a single
    # string, with data placed in network order (!)
    header = pack("!HHHHHH", ID, flags, num_questions, num_answers, num_auth,
            num_other)

    qname = stringToNetwork(hostname)
    if(isMX):
        qtype = 15 # request MX type
    else:
        qtype = 1 # request A type
    remainder = pack("!HH", qtype, 1)
    query = header + qname + remainder
    return query

def generateServerList():
    """
    Parses a text document with a list of the IP addresses of root servers

    Returns:
        list: A list of root servers formatted as strings
    """
    return [line.rstrip('\n') for line in open("root-servers.txt")]
    
def parseResponse(response, sock, domain, isMX):
    """
    Parses out the header of a DNS response then calls the function  that
    determines which record type it is.

    Args:
        response: a string containing the message to be parsed
        sock: an int containing the socket from which we are sending messages
        domain: a string containing the domain that is being searched
    Return:
        string: the IP address of the requested server    
    """
    inputList = bytearray(response)

    numAnsRR =  extractBytes(inputList, 2, 6)
    numAuthRR = extractBytes(inputList, 2, 8) 
    numAdditRR = extractBytes(inputList, 2, 10) 
    
    query = networkToString(response, 12)
    endIndex = query[1]+4
    bytesAfterQuery = response[endIndex:]
    afterQuery = bytearray(response[endIndex:])
    recordName, endIndex = networkToString(response, endIndex)
    endIndex -= 2
    bytesAfterQuery = response[endIndex:]
    afterQuery = bytearray(response[endIndex:])
    return parseRecord(response, bytesAfterQuery, afterQuery, numAnsRR, numAuthRR,
    endIndex, sock, domain, numAdditRR, isMX)

def extractBytes(byteList, numBytes, start):
    """
    A function that converts a list of bytes into an integer representation of
    the bytes contained

    Args:
        byteList: an integer containing the index of the list where we start
        adding
        numBytes: an integer containing the number of bytes to be added
    Return:
        an integer containing the bytes
    """
    value = byteList[start]
    for i in range(1, numBytes):
        value = (value << 8) + byteList[start + i]
    return value

def parseRecord(response, recordBytes, recordList, numAnswers, numAuths,
endIndex, sock, domain, numAdditRR, isMX):
    """
    A function that determines what kind of record has been returned

    Args:
        response: a bytes type object containing the original message
        recordBytes: a bytes type object containing the message starting at
        endIndex
        recordList: a list containing the message starting at endIndex
        numAnswers: an integer containing the number of Answers
        numAuths: an integer containing the number of Authoritative responses
        endIndex: an integer containing the last index parsed of the message
        sock: an integer containing the socket
        domain: a string containing the domain to be searched
        numAdditRR: an integer containing the number of Additional RRs
    Returns:
        a string containing the IP address
    """
     
    
    rType = extractBytes(recordList, 2, 2) 
    
    dataLength = extractBytes(recordList, 2, 9) 
  
    if rType == 1:
        ipAddress = parseRecordA(recordBytes, dataLength)
    elif rType == 2:
        ipAddress = parseRecordNS(response, recordBytes, recordList, numAuths, endIndex,
        0, domain, sock, numAdditRR, isMX) 
    elif rType == 5:
        ipAddress = parseRecordCNAME(response, numAnswers,endIndex, domain,
        sock, isMX)
    elif rType == 15:
        ipAddress = parseRecordMX(response, endIndex, sock, domain,
        numAdditRR, numAnswers)
    elif rType == 6:
        ipAddress = None
    return ipAddress 

def parseRecordA(record, dataLength):
    """
    A function that parses the A type record and extracts the IP address

    Args:
        record: a bytes type containing the message starting at the data
        section
        dataLength: an integer containing the length of the data
    Returns:
        a string containing the IP address
    """
    address = record[12:16]
    ip = socket.inet_ntoa(address)
    return ip

def parseRecordMX(response, endIndex, sock, domain, numAdditRR, numAnswers):
    """
    A function that parses the MX type record and sends out a new query for
    the domain received in the message

    Args:
        response: a bytes type object containing the original message
        endIndex: an integer containing the last parsed index of the response 
        sock: an integer containing the socket for sending messages
        domain: a string containing the domain for searching
    Returns:
        a string containing the IP address
    """

    authsParsed = 0
    if numAdditRR != 0:
        while authsParsed != numAnswers:
            serverName, endIndex = networkToString(response, endIndex + 14)
            nextAuthBytes = response[endIndex:] 
            nextAuthList = bytearray(response[endIndex:])
            authsParsed += 1
        authAnsBytes = response[endIndex:]
        authAnsList = bytearray(response[endIndex:])
        rType = extractBytes(authAnsList, 2, 2)
        dataLength = extractBytes(authAnsList, 2, 10)
        while(rType != 1):
            endIndex += 12 + dataLength
            authAnsBytes = response[endIndex:]
            authAnsList = bytearray(response[endIndex:])
            rType = extractBytes(authAnsList, 2, 2)
            dataLength = extractBytes(authAnsList, 2, 10)
        return parseRecordA(authAnsBytes, dataLength)
    else:
        serverName, endIndex = networkToString(response, endIndex +14)
        rootServerList = generateServerList()
        return constructAndSendQuery(serverName, rootServerList, sock,
        False)

def parseRecordCNAME(response, numAnswers, endIndex, domain, sock, isMX):
    """
    A function that parses CNAME records

    Args:
        response: a bytes type object containing the original message
        numAnswers: an integer containing the number of answers
        endIndex: an integer containing the last parsed index of the response 
        sock: an integer containing the socket for sending messages
        domain: a string containing the domain for searching
    Returns:
        a string containing the IP address
    """
    primaryName, endAnsIndex = networkToString(response, endIndex +12)
    if numAnswers > 1:
        nextAnswerBytes = response[endAnsIndex:] 
        nextAnswerList = bytearray(response[endAnsIndex:])
        numAnswers -= 1
        return parseRecord(response, nextAnswerBytes, nextAnswerList,
        numAnswers, 0, endAnsIndex, sock, domain, 0, isMX)  
    else:
        rootServerList = generateServerList()
        return constructAndSendQuery(primaryName, rootServerList, sock,
        isMX)

def parseRecordNS(response, authBytes, authList, numAuths, endIndex,
authsParsed, domain, sock, numAdditRR, isMX):
    """
    A function that parses the NS type records

    Args:
        response: a bytes type object containing the original message
        authBytes: a bytes type object containing the dns response starting at
        the authoritative response section
        authList: a list containing the dns response starting at the
        authoritative response section
        numAuths: an integer containing the number of Authoritative RRs
        endIndex: an integer containing the last parsed index of the response 
        authsParsed: an integer containing the number of Authoritative RRs already parsed
        sock: an integer containing the socket for sending messages
        domain: a string containing the domain for searching
        numAdditRR: an integer containing the number of additional RRs
    Returns:
        a string containing the IP Address
    """
    dataLength = extractBytes(authList, 2, 9)
    if numAdditRR != 0:
        while authsParsed != numAuths:
            serverName, endIndex = networkToString(response, endIndex +12)
            nextAuthBytes = response[endIndex:] 
            nextAuthList = bytearray(response[endIndex:])
            authsParsed += 1

        additParsed = 0
        ipList = []
        while additParsed != numAdditRR:

            endOfName = networkToString(response, endIndex)[1]
            endIndex = endOfName - 2
            authAnsBytes = response[endIndex:]
            authAnsList = bytearray(response[endIndex:])
        
            rType = extractBytes(authAnsList, 2, 2)

            dataLength = extractBytes(authAnsList, 2, 10)
            endIndex += 12 + dataLength
            if rType == 1:
                ip = parseRecordA(authAnsBytes, dataLength)
                if ip != None:
                    ipList.append(ip)
            additParsed += 1
        if(ipList == []):
            return None
        else:
            return constructAndSendQuery(domain, ipList, sock, isMX)
    else:
        serverName, endIndex = networkToString(response, endIndex +12)
        authAnsList = bytearray(response[endIndex:])
        rType = extractBytes(authAnsList, 2, 2)
        rootServerList = generateServerList()
        authIP =  constructAndSendQuery(serverName, rootServerList, sock,
        False)
        if(authIP == None):
            return authIP
        else:
            return constructAndSendQuery(domain, [authIP], sock, isMX)

def constructAndSendQuery(domain, ipList, sock, isMX):
    """
    A function that calls the constructQuery function then attempts to send it
    to a DNS server

    Args:
        domain: a string containing the domain to search for
        ip: a string containing the IP address to send the query to
        sock: an integer containing the socket id
        isMX: a boolean containing whether or not the query is MX type
    Returns:
        a string containing the IP Address
    """
    query = constructQuery(random.getrandbits(16), domain, isMX)
    for ip in ipList:
        try:
            print("Querying ", ip)
            sock.sendto(query, (ip, 53))
            response = sock.recv(4096)
            break
        except socket.timeout as e:
            print(ip, "has timed out")
    else:
        print("All servers in list timed out. Exiting program.")
        sys.exit()
    ipAddr = parseResponse(response, sock, domain, isMX)
    return ipAddr

def main(argv=None):
    if argv is None:
        argv = sys.argv

    rootServerList = generateServerList()

   
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)   # socket should timeout after 5 seconds
    if(len(argv) < 2 or argv[1] != '-m'):
        search = argv[1]
        isMX = False
    else:
        search = argv[2]
        isMX = True
    
    ipAdd = constructAndSendQuery(search, rootServerList, sock, isMX)
    sock.close()
    if(ipAdd == None):
        print("Could not resolve")
    else:
        print("The mail server for" if isMX else "The name", search, " resolves to: ", ipAdd)

if __name__ == "__main__":
    sys.exit(main())
