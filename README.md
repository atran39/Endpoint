endpoint.py usage

Extract zip to folder. Directory structure should be as follows:

\Endpoint
    \json
    \my
        - cuckoo_static_mod.py
        - endpoint.py
        - my_rules.yarc
        - endpoint.cmd
    \NtTrace
        - ...
    \yara
        - ...
    - endpoint_notes.txt

* NOTE* for endpoint.cmd, no additional software required
Usage:
  endpoint.cmd [prog].exe timeout
generates a nttrace_log.txt output located in the json directory

Required Software:
- Python Versions 2 & 3 (32b)
- Cuckoo for Python 2: install using 'pip install cuckoo' in the Python27 directory

Other Notes:
1. The user must install python 3.6 (32-bit) version!

2. Make sure agent.py is always opened with python2.7 by default (NOT python 3.6)

3. you should comment out the import yara line in enpoint.py

4. I had to make a few changes to your endpoint.py script related to calling your other scripts/yara rules.
    -Please make all your paths absolute. I tried to get relative paths to work but it doesnt.

    --> Dont know where the install directory is, can't use absolute paths

Usage:
navigate to Endpoint\my in command line. Run following command:
  python endpoint.py [prog].exe timeout

filename format is endpoint.json, output located in the json subfolder

program must be 32-bit, must be in path or have the full file path specified
