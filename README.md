# http-ripper
Parses PCAP files for HTTP 206 Partial Content and dumps them.

### Credit
This is a modified script from [@valinkrai](https://github.com/valinkrai). The goal was to make the script more functional, so you can use it for different scenarios. 

### What is this?
This script parses PCAP files (`.pcap`, `.pcapng`) for HTTP 206 - Partial Content responses. It will then attempt to reconstruct the original file. Usually in Wireshark, this isn't needed because Partial Content comes in order. However, if there's ever a scenario where the `Content-Range` is out of order, Wireshark has a hard time. This script will help solve that issue.

## Usage
```
python3 -m pip install scapy
python3 http-ripper.py [-h] -f FILE [-e EXTRACT] -o OUTPUT [-v]
python3 http-ripper.py -f packets.pcapng -o out.gif
```

### Considerations
Right now, `-e` is broken. I wanted to use Pyshark to create a new packet capture with the proper filters, but didn't work. If you have a pcap with multiple different partial content files, open it in Wireshark, apply the filter `http.response_for.uri contains "<file>" and http.response.phrase contains "Partial Content"` and then `File > Export Specified Objects`. 
