#!/usr/bin/env python
# -*- coding: utf-8 -*-


# --------------------------------------------------------------------
# (C) Copyright 2006-2017 Hewlett Packard Enterprise Development LP
#
# Author: Alex Sidorenko <asid@hpe.com>
#
# --------------------------------------------------------------------

# Print info about tasks

__version__ = "0.6"

from pykdump.API import *

from LinuxDump import percpu
from LinuxDump.Tasks import (TaskTable, Task, tasksSummary, ms2uptime,
     decode_tflags, print_namespaces_info, print_memory_stats)

from LinuxDump.BTstack import exec_bt, bt_summarize
from LinuxDump.fs import get_dentry_name
#import subprocess
GDB_SENTINEL = '(gdb) '
GDB_DATA_LINE = '~'
GDB_OOB_LINE = '^'
#print_memory_stats(8)
logd = memoize_cond(CU_LIVE | CU_TIMEOUT)(exec_crash_command_bg)("ps logd")
logd = logd.splitlines()[-1:]
print (logd)
logd = str(logd)
logd = ' '.join(logd.split())
print (logd.split(' ')[1])
pid = logd.split(' ')[1]
cmd = 'gcore' + ' ' + pid
print (cmd)
gcorelog = memoize_cond(CU_LIVE | CU_TIMEOUT)(exec_crash_command_bg)(cmd)
if (gcorelog):
    print (gcorelog)
else:
    # Timeout
    print ("")
core = 'core.'+pid+'.logd'
class Gdb(object):
    def __init__(self, gdb_path, elf):
        self.gdb_path = gdb_path
        self.elf_path = elf
        self._gdb = None
        print ("here")

    def open(self):
        self._gdb = subprocess.Popen(
            [self.gdb_path, '--interpreter=mi2', self.elf_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )
        self._flush_gdb()

    def close(self):
        self._gdb.communicate('quit')

    def __run(self, cmd):
        self._gdb.stdin.write(cmd.rstrip('\n') + '\n')
        self._gdb.stdin.flush()

        output = []
        oob_output = []
        while True:
            line = self._gdb.stdout.readline().rstrip('\r\n')
            if line == GDB_SENTINEL:
                break
            if line.startswith(GDB_DATA_LINE):
                line = line[1:]
                line = line[1:-1]
                if line.endswith('\\n'):
                    line = line[:-2]
                elif line.endswith('\n'):
                    line = line.rstrip('\n')
                output.append(line)
            if line.startswith(GDB_OOB_LINE):
                oob_output.append(line[1:])

        return (output, oob_output)

    def _run(self, cmd, num):
        lines, oob_lines = self.__run(cmd)
        if len(lines) != num:
            raise MyError(cmd, '\n'.join(lines + oob_lines))
        return lines[0]

    def _flush_gdb(self):
        while True:
            line = self._gdb.stdout.readline().rstrip('\r\n')
            if line == GDB_SENTINEL:
                break

    def field_offset(self, the_type, field):
        try:
            result = self._run('print /x (int)&(({0} *)0)->{1}'.format(the_type, field), 1)
            return hex_to_dec(result)
        except MyError:
            return 'None'

    def sizeof(self, the_type):
        try:
            result = self._run('print /x sizeof({0})'.format(the_type), 1)
            return hex_to_dec(result)
        except MyError:
            return 'None'

    def address_of(self, symbol):
        try:
            result = self._run('print /x &{0}'.format(symbol), 1)
            return int(result.split(' ')[-1], 16)
        except MyError:
            return 'None'

    def get_value_of(self, symbol):
        try:
            result = self._run('print /d {0}'.format(symbol), 1)
            return int(result.split(' ')[-1], 10)
        except MyError:
            return 'None'

    def get_str(self, symbol):
        try:
            result = self._run('print /s {0}'.format(symbol), 2)
            return str(result.split('\"')[1])
        except MyError:
            return 'None'


gdbmi = Gdb('/home/lipf/bin/aarch64-linux-android-gdb', '/home/lipf/tmp/ddr_test/0913/20/symbols/system/bin/logd')
#gdbmi.open()
#
#gdbmi.close()
