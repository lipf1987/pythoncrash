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
import subprocess
from pykdump.API import *

from LinuxDump import percpu
from LinuxDump.Tasks import (TaskTable, Task, tasksSummary, ms2uptime,
     decode_tflags, print_namespaces_info, print_memory_stats)

from LinuxDump.BTstack import exec_bt, bt_summarize
from LinuxDump.fs import get_dentry_name
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
#if (gcorelog):
#    print (gcorelog)
#else:
#    # Timeout
#    print ("")
core = 'core.'+pid+'.logd'

cmd = 'set' + ' ' + pid
#curr = memoize_cond(CU_LIVE | CU_TIMEOUT)(exec_crash_command_bg)(cmd)
#if (curr ):
#    print (curr )
#else:
#    # Timeout
#    print ("")
taskaddr = pid_to_task(int(pid)) 

def hex_to_dec(val):
    match = re.search('(0x[0-9a-fA-F]+)', val)
    return int(match.group(1), 16)

class MyError(Exception):
    def __init__(self, *args):
        self.value = '\n *** '.join([str(i) for i in args])

    def __str__(self):
        return self.value

class Gdb(object):
    def __init__(self, gdb_path, elf, core):
        self.gdb_path = gdb_path
        self.elf_path = elf
        self.core_path = core
        self._gdb = None

    def open(self):
        self._gdb = subprocess.Popen(
            [self.gdb_path, '--interpreter=mi2', self.elf_path, self.core_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE
        )
        self._flush_gdb()

    def close(self):
        self._gdb.communicate('quit'.encode('utf-8'))

    def __run(self, cmd):
        self._gdb.stdin.write((cmd.rstrip('\n') + '\n').encode('utf-8'))
        self._gdb.stdin.flush()

        output = []
        oob_output = []
        while True:
            #line = self._gdb.stdout.readline().rstrip('\r\n')
            line = self._gdb.stdout.readline()
            line = str(line,encoding='utf-8').rstrip('\r\n')
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
            #line = self._gdb.stdout.readline().rstrip('\r\n')
            line = self._gdb.stdout.readline()
            line = str(line,encoding='utf-8').rstrip('\r\n')
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
            result = self._run(('print /x &{0}'.format(symbol)), 1)
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
def android_log(num):
        numbers = {
                    0 : "UNKNOWN",
                    1 : "V",
                    2 : "D",
                    3 : "I",
                    4 : "W",
                    5 : "E",
                    6 : "I",
                    7 : "F",
                    8 : "S"
                }
        return numbers.get(num, None)

def logcat(opt):
    gdbmi = Gdb('/home/lipf/bin/aarch64-linux-android-gdb', '/home/lipf/tmp/ddr_test/0913/20/symbols/system/bin/logd','/home/lipf/tmp/ddr_test/0913/20/core.209.logd' )
    gdbmi.open()
    logBuf = gdbmi.get_value_of('logBuf')
    mLogId = gdbmi.field_offset('LogBufferElement', 'mLogId')
    mUid = gdbmi.field_offset('LogBufferElement', 'mUid')
    mPid = gdbmi.field_offset('LogBufferElement', 'mPid')
    mTid = gdbmi.field_offset('LogBufferElement', 'mTid')
    mMsg = gdbmi.field_offset('LogBufferElement', 'mMsg')
    mMsgLen = gdbmi.field_offset('LogBufferElement', 'mMsgLen')
    mDropped = gdbmi.field_offset('LogBufferElement', 'mDropped')
    mRealTime = gdbmi.field_offset('LogBufferElement', 'mRealTime')
    sizeof_mLogId = gdbmi.sizeof('log_id_t')
    sizeof_mUid = gdbmi.sizeof('uid_t')
    sizeof_mPid = gdbmi.sizeof('pid_t')
    sizeof_mTid = gdbmi.sizeof('pid_t')
    sizeof_mMsg = gdbmi.sizeof('char *')
    sizeof_mMsgLen  = gdbmi.sizeof('unsigned short')
    sizeof_mRealTime  = gdbmi.sizeof('log_time')
    __prev_ = readProcessMem(taskaddr, logBuf, 8)
    __next_ = readProcessMem(taskaddr, logBuf + 8, 8)
    __prev_ =  int.from_bytes(__prev_, byteorder='little')
    __next_  =  int.from_bytes(__next_ , byteorder='little')
    offset_prev = 0;
    offset_next = 8 * 1
    offset_msg  = 8 * 2
    print ( "logBuf %lx" % (logBuf))
    print(" mLogId %d " % (mLogId ))
    print(" mUId %d " % (mUid))
    print(" mPId %d " % (mPid))
    print(" mTId %d " % (mTid))
    print(" mMsg %d " % (mMsg))
    print(" mMsgLen  %d " % (mMsgLen))
    print(" mDropped  %d " % (mDropped))
    print(" mRealTime  %d " % (mRealTime))
    print(" sizeof_mTid   %d " % (sizeof_mTid))
    print ( "__prev_  %lx" % (__prev_ ))
    print ( "__next_  %lx" % (__next_ ))
    
    __next_ = readProcessMem(taskaddr, __next_ + offset_next , 8)
    __next_  =  int.from_bytes(__next_ , byteorder='little')
    Element = readProcessMem(taskaddr, __next_ + offset_msg , 8)
    Element =  int.from_bytes(Element, byteorder='little')
    print ( "__next_  %lx" % (__next_ ))
    LogId = int.from_bytes(readProcessMem(taskaddr, Element + mLogId , sizeof_mLogId ),byteorder='little')
    Uid = int.from_bytes(readProcessMem(taskaddr, Element + mUid , sizeof_mUid ),byteorder='little')
    Pid = int.from_bytes(readProcessMem(taskaddr, Element + mPid , sizeof_mPid ),byteorder='little')
    Tid = int.from_bytes(readProcessMem(taskaddr, Element + mTid , int(sizeof_mTid) ),byteorder='little')
    Msgaddr = int.from_bytes(readProcessMem(taskaddr, Element + mMsg , sizeof_mMsg ),byteorder='little')
    MsgLen = int.from_bytes(readProcessMem(taskaddr, Element + mMsgLen , sizeof_mMsgLen ),byteorder='little')
    if(MsgLen !=0 ):
        Msg = readProcessMem(taskaddr, Msgaddr, MsgLen)
        msg=''
        if(Msg[0] < 9):
            log = android_log(Msg[0])
            Msg = Msg[1:len(Msg) - 1].decode("ascii")
            for i in range(MsgLen - 2):
                if(Msg[i]=='\x00'):
                    msg =msg + ": "
                else:
                    msg =msg +  Msg[i]
            msg = msg.rstrip('\r\n')
            #print (" %d %d %d %d %d  %lx %s %s" % (LogId,Uid,Pid,Tid,MsgLen,Msgaddr, log,Msg[1:len(Msg) - 1].decode("ascii")))
            if(opt == 0):
                print (" %d %d %d %d %d  %lx %s %s" % (LogId,Uid,Pid,Tid,MsgLen,Msgaddr, log,msg))
            elif(opt == LogId):
                print (" %d %d %d %d %d  %lx %s %s" % (LogId,Uid,Pid,Tid,MsgLen,Msgaddr, log,msg))
    
    while __next_ != logBuf:
        __next_ = readProcessMem(taskaddr, __next_ + offset_next , 8)
        __next_  =  int.from_bytes(__next_ , byteorder='little')
        Element = readProcessMem(taskaddr, __next_ + offset_msg , 8)
        Element =  int.from_bytes(Element, byteorder='little')
        #print ( "__next_  %lx" % (__next_ ))
        LogId = int.from_bytes(readProcessMem(taskaddr, Element + mLogId , sizeof_mLogId ),byteorder='little')
        Uid = int.from_bytes(readProcessMem(taskaddr, Element + mUid , sizeof_mUid ),byteorder='little')
        Pid = int.from_bytes(readProcessMem(taskaddr, Element + mPid , sizeof_mPid ),byteorder='little')
        Tid = int.from_bytes(readProcessMem(taskaddr, Element + mTid , int(sizeof_mTid) ),byteorder='little')
        Msgaddr = int.from_bytes(readProcessMem(taskaddr, Element + mMsg , sizeof_mMsg ),byteorder='little')
        MsgLen = int.from_bytes(readProcessMem(taskaddr, Element + mMsgLen , sizeof_mMsgLen ),byteorder='little')
        if(MsgLen !=0):
            Msg = readProcessMem(taskaddr, Msgaddr, MsgLen)
            msg=''
            if(Msg[0] < 9):
                #print (" %s" % (Msg[1:]))
                log = android_log(Msg[0])
                Msg = Msg[1:len(Msg) - 1].decode("ascii")
                for i in range(MsgLen - 2):
                    if(Msg[i]=='\x00'):
                        msg =msg + ": "
                    else:
                        msg =msg +  Msg[i]
                msg = msg.rstrip('\r\n ')
                if(opt == 0):
                    print (" %d %d %d %d %d  %lx %s %s" % (LogId,Uid,Pid,Tid,MsgLen,Msgaddr, log,msg))
                elif(opt == LogId):
                    print (" %d %d %d %d %d  %lx %s %s" % (LogId,Uid,Pid,Tid,MsgLen,Msgaddr, log,msg))
                #print (" %d %d %d %d %d  %lx %s %s" % (LogId,Uid,Pid,Tid,MsgLen,Msgaddr, log,Msg[1:len(Msg) - 1].decode("ascii")))
                #print (" %d %d %d %d %d  %lx %s %s" % (LogId,Uid,Pid,Tid,MsgLen,Msgaddr, log,msg))
    
    gdbmi.close()
op =  OptionParser()

op.add_option("-m", dest="log", default = 0,
                action="store_true",
                help="main_log")
op.add_option("-r", dest="log", default = 1,
                action="store_true",
                help="radio_log")
op.add_option("-e", dest="log", default = 2,
                action="store_true",
                help="event_log")
op.add_option("-s", dest="log", default = 3,
                action="store_true",
                help="system_log")
op.add_option("-c", dest="log", default = 4,
                action="store_true",
                help="crash_log")
op.add_option("-a", dest="log", default = 5,
                action="store_true",
                help="security_log")
op.add_option("-k", dest="log", default = 6,
                action="store_true",
                help="kernel_log")
(o, args) = op.parse_args()
logcat(o.log)
