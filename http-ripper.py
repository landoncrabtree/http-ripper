from scapy.all import *
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

# http.response_for.uri contains "report.pdf" and http.response.phrase contains "Partial Content"
# pcap = pyshark.FileCapture(f"{args.file}", display_filter=f"http.response_for.uri contains \"{args.extract}\" and http.response.phrase contains \"Partial Content\"", output_file="tmp.pcap")
#print(f"http.response_for.uri contains \"{args.extract}\" and http.response.phrase contains \"Partial Content\"")
# pcap.load_packets()

file_length = 0
file_bytes = None
file_bytes_found = None

load_layer("http")
pkts = sniff(offline=f"{args.file}", session=TCPSession)
load_layer("http")

sessions = pkts.sessions()
for session in sessions:
    http_payload = b""
    http_header = b""
    
    for packet in sessions[session]:
        try:
            payload = bytes(packet[TCP].payload)
            http_header_exists = False
            try:
                http_header = payload[payload.index(b"HTTP/1.1"):payload.index(b"\r\n\r\n")+2]
                if http_header:
                    http_header_exists = True
            except:
                pass
            if not http_header_exists and http_payload:
                http_payload += payload
            elif http_header_exists and http_payload:
                http_payload = payload
            elif http_header_exists and not http_payload:
                http_payload = payload
        except:
            pass

    http_header = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header.decode("utf8")))
    try:
        if "application/pdf" in http_header["Content-Type"]:
            bytes_payload = http_payload[http_payload.index(b"\r\n\r\n")+4:]
        else:
            continue
    except:
        continue

    range_regex=r'bytes\ ([0-9]+)\-([0-9]+)\/([0-9]+)'
    try:
        result = re.search(range_regex, http_header["Content-Range"])
        start=int(result.group(1))
        end=int(result.group(2))
        maximum=int(result.group(3))
    except:
        continue
    if args.verbose:
        print(f"start: {start}, end: {end}, max: {maximum}")
    
    # Initialize file_bytes and file_bytes_found
    if file_length == 0:
        file_length = maximum
        file_bytes = [0] * file_length
        file_bytes_found = [0] * file_length

    if start == 0:
        
        # print(f"Has {low} - {high + 1}")
        # print(f"calc len: {high-low}")
        # print(f"actual len: {len(pdf_payload)}")
        # print(type(pdf_payload))
        # print(pdf_payload)
        # print()
        pass

    for i in range(start, end+1):
        file_bytes_found[i] = True
        file_bytes[i] = bytes_payload[i - start]
        if args.verbose:
            print(f"Byte {i} written: {chr(bytes_payload[i - start])}")

missing = 0
for file_byte_found in file_bytes_found:
    if not file_byte_found:
        missing += 1

if missing > 0:
    print(f"Missing {missing} bytes!")
    print(f"Received {file_length - missing} bytes out of {file_length} bytes")
    exit()

with open(f"{args.output}", 'wb') as f:
    f.write(bytearray(file_bytes))
    print(f"File written to {args.output}!")