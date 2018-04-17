#!/usr/bin/env python3

import os
import subprocess
import sys
import shutil
import argparse

import json
import yara
# from datetime import datetime
import re

# INIT_TIME= datetime.now().strftime("%m%d%y%H%M")

def yara_analysis(input_stream):
    rule_rgx = re.compile(r"^(?P<rule>\w+) (?P<file>)$")

    rule_table = {}

    for line in input_stream:
        rule_match = rule_rgx.match(line)
        if rule_match:
            rule_table[rule_match.group('rule')] = 1

    return json.dumps(rule_table, sort_keys=True, indent=4)

def nttrace_analysis(input_stream):
    input = input_stream.splitlines()
    # m = re.search(r"^Process (?P<pid>\d+) starting at (?P<base_addr>\w+)$", input[0])
    #
    # if m:
    #     pid = m.group('pid')
    #     base_addr = m.group('base_addr')
    # else:
    #     print(line)
    #     sys.exit(1)

    # dll_rgx = re.compile(r"^(?P<type>(?:Loaded)|(?:Unload)) (?:of )?DLL at (?P<addr>\w+)?(?P<path> \w*)?$")
    api_rgx = re.compile(r"^(?P<time>\d\d:\d\d:\d\d.\d\d\d): \[(?P<pid>\d*)\] (?P<fun>Nt\w+)\((?P<args>.*)\) => (?P<retval>\w+)(?: \[(?P<option>.*)\])?$")

    api_table = []

    file_num = 0
    prev_api = ''

    for line in input:
        api_match = api_rgx.match(line)
        if api_match:
            if api_match.group('fun') != prev_api:
                api_table.append((api_match.group('time'), api_match.group('fun')))
                prev_api = api_match.group('fun')

    return json.dumps(api_table, sort_keys=True, indent=4)

if __name__ == "__main__":
    programDescription = "Generate report of yara analysis, cuckoo static analysis, and NtTrace analysis"

    parser = argparse.ArgumentParser(description=programDescription)

    #--Flags--
    parser.add_argument('progname', help='Executable to be analyzed. Format should be [prog_path].exe')
    parser.add_argument('timeout', type=float, default=0, help='Timeout for NtTrace analysis. Use 0 to indicate no limit')

    args = parser.parse_args()
    args_dict = vars(args)

    if shutil.which(args_dict['progname']) is not None:
        prog = shutil.which(sys.argv[1])
    else:
        prog = os.path.abspath(sys.argv[1])

    timeout = args_dict['timeout']

    # m = re.search(r"\\(?P<exe_name>\w+).exe$", prog)
    # filename = m.group('exe_name') + '_' + INIT_TIME + '.json'
    filename = 'endpoint.json'

    yara_output = subprocess.run(['../yara/yara32.exe', './my_rules.yarc', prog], stdout=subprocess.PIPE)
    yara_json = json.loads(yara_analysis(yara_output.stdout))

    cuckoo_output = subprocess.run(['py', '-2', 'cuckoo_static_mod.py', prog], stdout=subprocess.PIPE)
    cuckoo_json = json.loads(cuckoo_output.stdout)

    nttrace = subprocess.Popen(['../NtTrace/NtTrace.exe', '-pid', '-nl', '-time', prog], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if timeout != 0:
            nt_out, nt_err = nttrace.communicate(timeout = timeout)
    except subprocess.TimeoutExpired:
        nttrace.kill()

    nt_out, nt_err = nttrace.communicate()
    nttrace_json = json.loads(nttrace_analysis(nt_out.decode("utf-8")))

    f = open('../json/' + filename, 'w')
    json.dump({"yara":yara_json, "cuckoo":cuckoo_json, "nttrace": nttrace_json}, f, sort_keys=True, indent=4)
