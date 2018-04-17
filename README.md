# Endpoint
Endpoint malware detection tool

endpoint.py usage

Extract zip to folder. Directory structure should be as follows:

\Endpoint
    \json
    \my
        - cuckoo_static_mod.py
        - endpoint.py
        - my_rules.yarc
    \NtTrace
        - ...
    \yara
        - ...
    - endpoint_notes.txt

Required Software:
- Python Versions 2 & 3
- Cuckoo for Python 2: install using 'pip install cuckoo' in the Python27 directory

Usage:
navigate to Endpoint\my in command line. Run following command:
  python endpoint.py [prog].exe timeout

filename format is endpoint.json, output located in the json subfolder

program must be 32-bit, must be in path or have the full file path specified