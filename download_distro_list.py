#!/usr/bin/python
import os, posixpath
import urllib.request, urllib.parse
import uuid
import csv

DOWNLOADS_DIR = './temp'
ISO_LIST = 'iso-list.txt'
MASTER_CHECKSUM_LIST_CSV = 'iso-checksums-master.csv'
SECTION_DIVIDER = "=========================================================================="


class ISOHash:

    HASH_TYPES = ['MD5','SHA1','SHA2','SHA256','SHA512']

    def __init__(self, fileName, hashType, hashValue) -> None:
        self.fileName = fileName
        self.guid = uuid.uuid4()
        if not ((isinstance(hashType, str)) and (hashType in self.HASH_TYPES)):
            raise ValueError(f"unexpected hash type; got {hashType}; need one of {self.HASH_TYPES}")
        self.hashType = hashType
        self.hashValue = hashValue

    def __str__(self) -> str:
        return f"{self.fileName}={self.hashValue} ({self.hashType})"

    def __repr__(self) -> str:
        return f"{type(self).__name__}(fileName={self.fileName}, guid={self.guid}, hashType={self.hashType}, hashValue={self.hashValue})"
        
    def getCSVRow(self) -> list:
        return [str(self.fileName),str(self.hashType),str(self.hashValue),str(self.guid)]
    
    def getCSVFields(self) -> list:
        return [str("fileName"),str("hashType"),str("hashValue"),str("guid")]
              

def convert_ChecksumFiles(localList):

    newMasterList = []

    dummyISO = ISOHash("derp","SHA512","123")
    newMasterList.append(dummyISO.getCSVFields())
    del dummyISO

    print("\n\nChecksum List: \n")
    for item in localList:

        section, path = item[0], item[2]
        fileName = path.split('/')[-1]

        print("  Section:   ", section)
        print("  Full Path: ", path)
        print("  File Name: ", fileName, flush=True)

        if "alma" in section:
            # Handle straight checksums
            if "live" in section:
                newMasterList.extend(convert_StraightSHAXChecksums(path, "SHA256"))
            # Handle PGP signed checksums
            else:
                newMasterList.extend(convert_PGPSignedMsgChecksums(path))

        elif "manjaro" in section:
            # Handle straight SHA1 checksums
            newMasterList.extend(convert_StraightSHAXChecksums(path, "SHA1"))

        elif "arch"     in section or \
             "centos-7" in section or \
             "garuda"   in section or \
             "debian"   in section or \
             "ubuntu"   in section:
            # Handle straight SHA256 checksums
            newMasterList.extend(convert_StraightSHAXChecksums(path, "SHA256"))

        elif ("centos" in section and "stream" in section) or \
             "fedora" in section or \
             "rocky"  in section:
            # Handle PGP signed SHA256 checksums (not PGP signed but same message format)
            newMasterList.extend(convert_PGPSignedMsgChecksums(path))

    print("", flush=True)

    return newMasterList


def convert_PGPSignedMsgChecksums(path):

    currentFileList = []

    with open(path, 'r', encoding="utf-8") as f:

        lines = f.readlines()

        for line in lines:

            if line.startswith('SHA256'):

                lineParts = line.split(' ')
                # Get the file name - the second word and remove the parentheses
                name = lineParts[1][1:-1]
                #print("    PGP - File name:  ", name)

                # Get the hash type - the first word
                hashType = lineParts[0]
                #print("    PGP - Hash type:  ", hashType)

                # Get the SHA256 value - the fourth word
                hashValue = lineParts[3]

                if "\n" in hashValue:
                    hashValue = hashValue.replace("\n", "")
                #print("    PGP - Hash value: ", hashValue, flush=True)

                currentISOHash = ISOHash(name, hashType, hashValue)

                currentFileList.append(currentISOHash.getCSVRow())

        f.close()
        
    return currentFileList


def convert_StraightSHAXChecksums(path, algorithm):

    currentFileList = []

    with open(path, 'r', encoding="utf-8") as f:

        lines = f.readlines()

        for line in lines:

            lineParts = line.split(' ')

            # If there are two spaces between the hash and the file name,
            # (separated like: '<FILE_HASH>  <FILE_NAME>')
            # remove the "empty" item in the list between the hash and file name
            # (some are separated like: '<FILE_HASH> *<FILE_NAME>' - a space and asterisk)
            if (len(lineParts) == 3):
                lineParts.remove('')

            # Get the file name - the second word
            name = lineParts[1]
            if "*" in name:
                name = name.replace("*", "")
            if "\n" in name:
                name = name.replace("\n", "")
            #print("    SHAX - File name:  ", lineParts[1])

            # Get the hash type - passed in as an argument
            #print("    SHAX - Hash type:  ", algorithm)

            # Get the SHA256 value - the first word
            hashValue = lineParts[0]
            #print("    SHAX - Hash value: ", lineParts[0], flush=True)

            currentISOHash = ISOHash(name, algorithm, hashValue)

            currentFileList.append(currentISOHash.getCSVRow())

        f.close()

    return currentFileList


def download_ISO(url, sectionName):

    response = urllib.request.urlopen(url)
    
    # Split on the rightmost / and take everything on the right side of that
    name = urllib.parse.unquote(posixpath.basename(urllib.parse.urlparse(response.url).path))
    #print('  Downloading iso-image file: ', name)

    # Combine the name and the downloads directory to get the local filename
    dirName = os.path.join(DOWNLOADS_DIR, sectionName)
    fileName = os.path.join(dirName, name)

    return fileName

    # Download the file if it does not exist
    if not os.path.isdir(dirName):
        os.mkdir(dirName)
        print("  Make directory: ", dirName)
    else: 
        print("  Oops...")
        return None

    if not os.path.isfile(fileName):
        with open(fileName, 'wb') as fw:
            fw.write(response.read())
            print('  save file ', fileName)
            response.close()


def download_Checksum(url, sectionName):

    response = urllib.request.urlopen(url)
    
    # Split on the rightmost / and take everything on the right side of that
    name = urllib.parse.unquote(posixpath.basename(urllib.parse.urlparse(response.url).path))
    #print('  Downloading checksum file:  ', name)

    # Combine the name and the downloads directory to get the local filename
    dirName = os.path.join(DOWNLOADS_DIR, sectionName)
    fileName = os.path.join(dirName, name)

    # Download the file
    if not os.path.isdir(dirName):
        os.mkdir(dirName)
        #print("  Make directory: ", dirName)

    with open(fileName, 'wb') as fw:
        fw.write(response.read())
        #print('  Save file:                  ', fileName)
        response.close()
        fw.close()

    return fileName


def main():

    sectionName = "null"

    checksumFileListFields = ["Section","URL","Local Path"]
    checksumFileList = []
    simpleChecksumCSVFileName = os.path.join(DOWNLOADS_DIR, "nonconverted-checksums.csv")

    isoFileList = []

    # Open the file for reading
    with open(ISO_LIST, 'r', encoding="utf-8") as f:
        
        # Read all lines into variable
        lines = f.readlines()
        
        # For every line in the file
        for line in lines:
            
            # If the line is not a comment, section name, or blank
            if not line.startswith('#') and not line.strip() == "":
                
                # If the line is an iso file URL
                if line.startswith('['):
                    
                    # Set the section name, stripping the square brackets off
                    sectionName = line[1:-2]
                    print("\n", SECTION_DIVIDER)
                    print("\nMoving to section:", sectionName, "\n")

                elif line.endswith('.iso\n'):

                    # Call the "download ISO" function with the URL
                    #download_ISO(line, sectionName)
                    continue

                # If the line is a checksum file URL
                elif line.__contains__('sum') or \
                     line.__contains__('SUM') or \
                     line.__contains__('sha'):

                    # Call the "download checksum" function with the URL and section name
                    # Append to the checksumFileList: "section name, "URL", and "local file path"
                    checksumFileList.append([sectionName, line[:-1], (download_Checksum(line, sectionName))])

                else:

                    print("YOU A DUM-DUM...")
                    print(line)

    f.close()

    with open(simpleChecksumCSVFileName, 'w') as csvfile:

        csvwriter = csv.writer(csvfile)

        csvwriter.writerow(checksumFileListFields)
        csvwriter.writerows(checksumFileList)

    csvfile.close()

    # Convert the checksum list into a more usable data format (CSV)
    masterChecksumListCSV = convert_ChecksumFiles(checksumFileList)
    
    with open(MASTER_CHECKSUM_LIST_CSV, 'w') as csvfile:

        csvwriter = csv.writer(csvfile)

        csvwriter.writerows(masterChecksumListCSV)

    csvfile.close()

if __name__ == "__main__":
    main()