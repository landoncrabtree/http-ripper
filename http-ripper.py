import re
import argparse
import pyshark

parser = argparse.ArgumentParser()

# -f <pcap file>
# -e <file to extract>
# -o <output file>
# -v <verbose>

parser.add_argument("-f", "--file", help="pcap file to parse", required=True)
parser.add_argument("-e", "--extract", help="file to extract", required=False)
parser.add_argument("-o", "--output", help="output file", required=True)
parser.add_argument("-v", "--verbose", help="verbose output", action="store_true")
args = parser.parse_args()

if args.extract:
    pcap_filter = f"http.response_for.uri contains \"{args.extract}\" and http.response.phrase contains \"Partial Content\""
    print(pcap_filter)
    pcap = pyshark.FileCapture(f"{args.file}", display_filter=pcap_filter)
else:
    pcap = pyshark.FileCapture(f"{args.file}", display_filter=f"http.response.phrase contains \"Partial Content\"")
pcap.load_packets()


filesize = 0
data = None
extracted = 0

for packet in pcap:
    as_string = str(packet.http)
    for line in as_string.splitlines():
        if "Content-Range" in line:
            match = re.search(r'bytes (\d+)-(\d+)/(\d+)', line)
            start, end, _filesize = int(match.group(1)), int(match.group(2)),int(match.group(3))
            if filesize == 0:
                filesize = _filesize
                data = [0x0] * filesize
            if args.verbose:
                print(f"start: {start}, end: {end}, filesize: {filesize}")
            j = 0
            file_data = packet.http.file_data.raw_value
            file_data = bytearray.fromhex(file_data)
            if args.verbose:
                print(file_data)
                print(len(file_data))
                print(end-start)
            for i in range(start, end+1):
                data[i] = file_data[j]
                extracted += 1
                j += 1

try:
    with open(args.output, "wb") as f:
        f.write(bytes(data))
except:
    print("Error extracting file")
            
            
            
            
    
