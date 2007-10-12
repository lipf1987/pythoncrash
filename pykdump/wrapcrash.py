#
# -*- coding: latin-1 -*-
# Time-stamp: <07/10/11 13:52:41 alexs>

# Functions/classes used while driving 'crash' externally via PTY
# Most of them should be replaced later with low-level API when
# using Python loaded to crash as shared library
# There are several layers of API. Ideally, the end-users should only call
# high-level functions that do not depend on internal

# Copyright (C) 2006-2007 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2006-2007 Hewlett-Packard Co., All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.



import sys
import string, re
import struct

import threading
import types
from StringIO import StringIO
import pprint

pp = pprint.PrettyPrinter(indent=4)

import tparser
import nparser

experimental = False
experimental = True

debug = False

#GDBStructInfo = tparser.GDBStructInfo
GDBStructInfo = nparser.GDBStructInfo


import Generic as Gen
from Generic import Bunch, TypeInfo, VarInfo, SUInfo

hexl = Gen.hexl


# GLobals used my this module



# the default number of elements returned from list traversal

_MAXEL = 10000

# A well-known way to remove dups from sequence
def unique(s):
    u = {}
    for x in s:
        u[x] = 1
    return u.keys()

# An auxiliary function: create a multi-dim list based on index list,
# e.g. [2,3,4] =>  a[2][3][4] filled with None
def multilist(mdim):
    d1 = mdim[0]
    if (len(mdim) > 1):
        a = []
        for i in range(d1):
            a.append(multilist(mdim[1:]))
    else:
        a =  [None for i in range(d1)]
    return a

def _arr1toM(dims, arr1):    
    # We do this for 2- and 3-dim only
    out = multilist(dims)
    if (len(dims) == 2):
        I = dims[0]
        J = dims[1]
        for i in range(I):
            for j in range(J):
                out[i][j] = arr1[i*J+j]

    elif (len(dims) == 3):
        I = dims[0]
        J = dims[1]
        K = dims[2]
        for i in range(I):
            for j in range(J):
                for k in range(K):
                    out[i][j] = arr1[i*J*K+j*K +k]
    else:
        raise TypeError, "Array with dim >3"
    return out

    
# Classes to be used for basic types representation
# We adjust 'stype' if needed

def update_TI(f, e):
    # These fields are always set
    t_size = e["typelength"]
    f.codetype = e["codetype"]
    f.stype = e_to_tagname(e)

    f.size = t_size

    if (e.has_key("dims")):
        f.dims = e["dims"]

    if (e.has_key("stars")):
        f.ptrlev = e["stars"]

    if (e.has_key("uint")):
        f.uint = e["uint"]
    else:
        f.uint = None


    if (e.has_key("typedef")):
        f.typedef = e["typedef"]        # The initial type

    if (e.has_key("ptrbasetype")):
        f.ptrbasetype = e["ptrbasetype"] # The base type of pointer

    # A special case is a struct/union without tag. In this case
    # we create an artifical name for it

    # If we have a body, get details
    if (e.has_key("body")):
        tag = e_to_tagname(e)
        # Add this typeinfo to cache
        ff = SUInfo(tag, False)
        if (not ff.PYT_body):
            update_SUI(ff, e)
        f.details = ff

def update_TI_fromgdb(f, sname):
    e = crash.gdb_typeinfo(sname)
    update_TI(f, e)

# Choose a tag used for caching:
# - if we have typedef, use it
# - otherwise, use the real type
# - if the tag is non-descriptive (e.g. embedded structs), create a fakename
def e_to_tagname(e):
    if (e.has_key("typedef")):
        tag = e["typedef"]        # The initial type
    else:
        tag = e["basetype"]
    # Do we just one word in basetype? If yes, create a proper tag
    if (tag in ('struct', 'union')):
        tag = tag + " fake-" + str(id(e))

    return tag
        
 
   
def update_SUI(f, e):
    f.PYT_size = f.size = e["typelength"]
    for ee in e["body"]:
        fname = ee["fname"]
        f1 = VarInfo(fname, False)
        ti = TypeInfo('', False)
        update_TI(ti, ee)
        f1.ti = ti
        f1.bitoffset = ee["bitoffset"]
        f1.offset = f1.bitoffset/8
        if (ee.has_key("bitsize")):
            f1.bitsize = ee["bitsize"]

        f.append(fname, f1)


def update_TI_fromgdb(f, sname):
    e = crash.gdb_typeinfo(sname)
    update_TI(f, e)
    

def update_SUI_fromgdb(f, sname):
    try:
        e = crash.gdb_typeinfo(sname)
    except crash.error:
        raise TypeError, "no type " + sname
    update_SUI(f, e)

class StructResult(object):
    def __init__(self, sname, addr):
       	self.PYT_symbol = sname
	self.PYT_addr = addr
        self.PYT_sinfo = SUInfo(sname)
        self.PYT_size = self.PYT_sinfo.PYT_size;

    def __getattr__(self, name):
        try:
            fi = self.PYT_sinfo[name]
        except KeyError:
            # This is ugly - but I have not found a better way yet
            ind = name.find('__')
            if (ind > 0):
                name = name[ind:]
            fi = self.PYT_sinfo[name]
            
        reader = fi.reader
        addr = self.PYT_addr + fi.offset
        return reader(addr)

    def __str__(self):
        return "<%s 0x%x>" % \
               (self.PYT_symbol, self.PYT_addr)

    def __repr__(self):
        return "StructResult <%s 0x%x> \tsize=%d" % \
               (self.PYT_symbol, self.PYT_addr, self.PYT_size)
    
    # Backwards compatibility
    def __nonzero__(self):
        return True

    def __len__(self):
        return self.PYT_size

    def hasField(self, fname):
        return self.PYT_sinfo.has_key(fname)

    def isNamed(self, sname):
        return sname == self.PYT_symbol

    # Cast to another type. Here we assume that that one struct resides
    # as the first member of another one, this is met frequently in kernel
    # sources
    def castTo(self, sname):
        return StructResult(sname, self.PYT_addr)

    def __getitem__(self, name):
        return self.PYT_sinfo[name]

# A factory function for integer readers
def intReader(vi):
    def signedReader(addr):
        s = readmem(addr, size)
        return mem2long(s, signed = True)
    def unsignedReader(addr):
        s = readmem(addr, size)
        return mem2long(s)
    def signedBFReader(addr):
        s = readmem(addr, size)
        val = mem2long(s)
        val = (val >> bitoffset) & mask
        sign = val >> (bitsize - 1)
        if (sign):
            return val - mask -1
        else:
            return val
    def unsignedBFReader(addr):
        s = readmem(addr, size)
        val = mem2long(s)
        val = (val>>bitoffset) & mask
        return val

    def charArray(addr):
        s = readmem(addr, dim1)
        val = SmartString(s, addr, None)
        return val

    # Arrays
    def signedArrayReader(addr):
        s = readmem(addr, totsize)
        val = mem2long(s, signed = True, array = elements)
        if (len(dims) > 1):
            val = _arr1toM(dims, val)
        return val

    def unsignedArrayReader(addr):
        s = readmem(addr, totsize)
        val =  mem2long(s, array = elements)
        if (len(dims) > 1):
            val = _arr1toM(dims, val)
        return val

    # A special case like unsigned char tb_data[0];
    # Return address
    def zeroArrayReader(addr):
        return addr

    ti = vi.ti
    size = ti.size
    bitsize = vi.bitsize
    if (bitsize != None):
        bitoffset = vi.bitoffset - vi.offset * 8
    uint = ti.uint
    dims = ti.dims
    elements = ti.elements
    totsize = size * elements
    if (debug):
        print "Creating an intReader size=%d" % size, \
              "uint=", uint, \
              "bitsize=", bitsize, "bitoffset=", bitoffset

    if (dims != None and len(dims) == 1 and ti.stype == 'char'):
        # CharArray
        dim1 = dims[0]
        return charArray
    elif (dims != None and  len(dims) == 1 and dims[0] == 0):
        return zeroArrayReader
    elif (uint == None or uint):
        if (bitsize == None):
            if (dims == None):
                return unsignedReader
            else:
                return unsignedArrayReader
        else:
            mask = (~(~0<<bitsize))
            return unsignedBFReader
    else:
        if (bitsize == None):
            if (dims == None):
                return signedReader
            else:
                return signedArrayReader
        else:
            mask = (~(~0<<bitsize))
            return signedBFReader


# A factory function for struct/union readers
def suReader(vi):
    def reader1(addr):
        return StructResult(stype, addr)

    def readerarr(addr):
        out = []
        for i in range(elements):
            sr = StructResult(stype, addr + i * size)
            out.append(sr)
        if (len(dims) > 1):
            out = _arr1toM(dims, out)
        return out

    # A special case, e.g. struct sockaddr_un name[0]
    def zeroArrayReader(addr):
        return StructResult(stype, addr)

    ti = vi.ti
    dims = ti.dims
    elements = ti.elements
    size = ti.size
    stype = ti.stype

    if (elements == 1):
        return reader1
    elif (elements == 0):
        return zeroArrayReader
    else:
        return readerarr
    

# A factory function for pointer readers
def ptrReader(vi, ptrlev):
    def strPtr(addr):
        ptr = readPtr(addr)
        # If ptr = NULL, return None, needed for backwards compatibility
        if (ptr == 0):
            return None
        s = readmem(ptr, 256)
        return SmartString(s, addr, ptr)
    def genPtr(addr):
        ptr = readPtr(addr)
        tptr = tPtr(ptr, vi)
        return tptr

    def funcPtr(addr):
        ptr = readPtr(addr)
	if (ptr and machine == "ia64"):
	    ptr = readPtr(ptr)
        return ptr

    def ptrArray(addr):
        val = []
        for i in range(elements):
            ptr = readPtr(addr + i * size)
            val.append(tPtr(ptr, vi))
        if (len(dims) > 1):
            val = _arr1toM(dims, val)
        return val
   
    # A special case like struct x8664_pda *_cpu_pda[0];
    # Convert it internally to struct x8664_pda **_cpu_pda;
    # 
    def ptrArr0(addr):
        tptr = tPtr(addr, vi)
        tptr.ptrlev += 1
        return tptr

    ti = vi.ti
    dims = ti.dims
    elements = ti.elements
    size = ti.size
    stype = ti.stype
        
    if (ptrlev == 1 and stype == 'char'):
        reader = strPtr
    elif (ti.ptrbasetype == 6):      # A pointer to function
	reader = funcPtr
    else:
        if (dims != None):
            if (len(dims) == 1 and elements == 0):
                return ptrArr0
            else:
                return ptrArray
        else:
            # A generic ptr
            reader = genPtr
    return reader

        
    
# Struct/Union info representation with methods to append data

class _GDB:
    TYPE_CODE_PTR = 1		#/* Pointer type */
    TYPE_CODE_ARRAY = 2		#/* Array type with lower & upper bounds. */
    TYPE_CODE_STRUCT = 3	#/* C struct or Pascal record */
    TYPE_CODE_UNION = 4		#/* C union or Pascal variant part */
    TYPE_CODE_ENUM = 5		#/* Enumeration type */
    TYPE_CODE_FUNC = 6		#/* Function type */
    TYPE_CODE_INT = 7		#/* Integer type */
    TYPE_CODE_FLT = 8
    TYPE_CODE_VOID = 9



            


# An auxiliary class to be used in StructResult to process dereferences

# Warning: this is obsoleted and will go away sooner or later

import inspect
class Dereference:
    __first = True
    def __init__(self, sr):
	#raise AttributeError, "Dereference"
	if (Dereference.__first):
	    frame, fn, lineno, subr, stmts, sl = inspect.stack()[-2]
	    print "!!!Warning: do not use Deref attribute for non-pointers"
	    print "!!!  trying to use it for", sr
	    print "!!!  at line %d of %s (%s)" % (lineno, fn, subr)
	    print "!!!\t", stmts[sl]
	    Dereference.__first = False
        self.sr = sr
    def __getattr__(self, f):
        # Get address from the struct.
        #addr = self.sr.__getattr__(f)
	addr = readPtr(Addr(self.sr, f))
	if (addr == 0):
	    msg = "\nNULL pointer %s->%s" % (
	                                       str(self.sr), f)
	    raise IndexError, msg

        stype = self.sr.PYT_sinfo[f].basetype
        return readSU(stype, addr) 

# Wrapper functions to return attributes of StructResult

def Addr(obj, extra = None):
    if (isinstance(obj, StructResult)):
        # If we have extra set, we want to know the address of this field
        if (extra == None):
            return obj.PYT_addr
        else:
            off = obj.PYT_sinfo[extra].offset
            return obj.PYT_addr + off
    elif (isinstance(obj, SmartString)):
          return obj.addr
    else:
        raise TypeError, type(obj)

# Dereference a tPtr object - at this moment 1-dim pointers to SU only
def Deref(obj):
    if (isinstance(obj, tPtr)):
        return obj.Deref
    else:
        raise TypeError, "Trying to dereference a non-pointer " + str(obj)


# When we do readSymbol and have pointers to struct, we need a way
# to record this info instead of just returnin integer address

# To make dereferences faster, we store the basetype and ptrlev

class tPtr(long):
    def __new__(cls, l, vi):
        return long.__new__(cls, l)
    def __init__(self, l, vi):
        # If ptype is a string, treat it as typename and assume we
        # want to declare a pointer to this type
        if (type(vi) == type("")):
            # This is a hack, please reimplement
            raise TypeError, "not implemented yet"
            #ptype = whatis(ptype, ptype + " dummy;")
        elif (isinstance(vi, tPtr)):
            # A copy constructor
            raise TypeError
        else:
            # Store the basetype and number of stars separately
            self.vi = vi
            self.ptrlev = vi.ti.ptrlev
    # For pointers, index access is equivalent to pointer arithmetic
    def __getitem__(self, i):
        sz1 = self.vi.ti.size
        return self.getDeref(i)
    def getDeref(self, i = None):
        addr = long(self)
        if (addr == 0):
            msg = "\nNULL pointer %s" % repr(self)
            raise IndexError, msg

        if (self.ptrlev == 1):
            dereferencer = self.vi.dereferencer
            if (i != None):
                addr += i * self.vi.tsize
            return dereferencer(addr)
        else:
            if (i != None):
                addr += i * self.vi.ti.size
            ntptr = tPtr(readPtr(addr), self.vi)
            ntptr.ptrlev = self.ptrlev - 1
            return ntptr
    def __repr__(self):
        stars = '*' * self.ptrlev
        return "<tPtr addr=0x%x ctype='%s %s'>" % \
               (self, self.vi.ti.stype, stars)
    Deref = property(getDeref)

    # Backwards compatibility
    def getPtype(self):
        return self.vi
    ptype = property(getPtype)


class SmartString(str):
    def __new__(cls, s, addr, ptr):
        return str.__new__(cls, s.split('\0')[0])
    def __init__(self, s, addr, ptr):
        self.addr = addr
        self.ptr = ptr
        self.__fullstr = s
    def __long__(self):
        return self.ptr
    def __getslice__(  self, i, j):
	return self.__fullstr.__getslice__(i, j)
    def __getitem__(self, key):
	return self.__fullstr.__getitem__(key)
    

# Print the object delegating all work to GDB. At this moment can do this
# for StructResult only

def printObject(obj):
    if (isinstance(obj, StructResult)):
        cmd = "p *(%s *)0x%x" %(obj.PYT_symbol, obj.PYT_addr)
        print cmd
        s = exec_gdb_command(cmd)
        # replace the 1st line with something moe useful
        first, rest = s.split("\n", 1)
	print "%s 0x%x {" %(obj.PYT_symbol, obj.PYT_addr)
        print rest
    else:
        raise TypeError
        

# =============================================================
#
#           ======= read functions =======
#
# =============================================================


def readU16(addr):
    s = readmem(addr, 2)
    return mem2long(s)

def readU32(addr):
    s = readmem(addr, 4)
    return mem2long(s)

def readS32(addr):
    s = readmem(addr, 4)
    return mem2long(s, signed = True)
    
# addr should be numeric here
def readSU(symbol, addr):
    return StructResult(symbol, addr)

#          ======== read arrays =========


# Read an array of structs/unions given the structname, start and dimension
def readSUArray(suname, startaddr, dim=0):
    # If dim==0, return a Generator
    if (dim == 0):
        return SUArray(suname, startaddr)
    sz = struct_size(suname)
    # Now create an array of StructResult.
    out = []
    for i in range(0,dim):
        out.append(StructResult(suname, startaddr+i*sz))
    return out


#          ======== read a chunk of physical memory ===

def readProcessMem(taskaddr, uvaddr, size):
    # We cannot read through the page boundary
    out = []
    while (size > 0):
        paddr = uvtop(taskaddr, uvaddr)

        cnt = crash.PAGESIZE - crash.PAGEOFFSET(uvaddr)
        if (cnt > size):
            cnt = size

        out.append(readmem(paddr, cnt, crash.PHYSADDR))
        uvaddr += cnt
        size -= cnt
    return string.join(out)
    
#          ======== read lists  =========


# Emulate list_for_each + list_entry
# We assume that 'struct mystruct' contains a field with
# the name 'listfieldname'
# Finally, by default we do not include the address f the head itself
#
# If we pass a string as 'headaddr', this is the symbol pointing
# to structure itself, not its listhead member
def readSUListFromHead(headaddr, listfieldname, mystruct, maxel=_MAXEL,
                     inchead = False):
    msi = getStructInfo(mystruct)
    offset = msi[listfieldname].offset
    if (type(headaddr) == types.StringType):
        headaddr = sym2addr(headaddr) + offset
    out = []
    for p in readList(headaddr, 0, maxel, inchead):
        out.append(readSU(mystruct, p - offset))
    return out

# Read a list of structures connected via direct next pointer, not
# an embedded listhead. 'shead' is either a structure or tPtr pointer
# to structure

def readStructNext(shead, nextname):
    if (not isinstance(shead, StructResult)):
        if (shead == 0):
            return []
        else:
            shead = Deref(shead)
    stype = shead.PYT_symbol
    offset = shead.PYT_sinfo[nextname].offset
    out = []
    for p in readList(Addr(shead), offset):
        out.append(readSU(stype, p))
    return out 

#    ======= Arrays Without Dimension =============
#
#  In some cases we have declarations like
#  struct AAA *ptr[];

class tPtrDimensionlessArray(object):
    def __init__(self, ptype, addr):
        self.ptype = ptype
        self.addr = addr
        self.size = pointersize
    def __getitem__(self, key):
        addr = readPtr(self.addr + pointersize * key)
        return tPtr(addr, self.ptype)

#     ======= return a Generator to iterate through SU array
def SUArray(sname, addr, maxel = _MAXEL):
    size = getSizeOf(sname)
    addr -= size
    while (maxel):
        addr += size
        yield readSU(sname, addr)
    return


# Walk list_Head and return the full list (or till maxel)
#
# Note: By default we do not include the 'start' address.
# This emulates the behavior of list_for_each_entry kernel macro.
# In most cases the head is standalone and other list_heads are embedded
# in parent structures.

def readListByHead(start, offset=0, maxel = _MAXEL):
    return readList(start, offset, maxel, False)

# An alias
list_for_each_entry = readListByHead

# readList returns the addresses of all linked structures, including
# the start address. If the start address is 0, it returns an empty list

# For list declared using LIST_HEAD, the empty list is when both next and prev
# of LIST_HEAD point to its own address

def readList(start, offset=0, maxel = _MAXEL, inchead = True):
    if (start == 0):
        return []
    if (inchead):
        count = 1
        out = [start]
    else:
        out = []
        count = 0
    next = start
    while (count < maxel):
        next = readPtr(next + offset)
        if (next == 0 or next == start):
            break
        out.append(next)
        count += 1
    return out

#     ======= get list size for LIST_HEAD =====
def getListSize(addr, offset, maxel):
    if (addr == 0):
        return 0


    count = 0                           # We don't include list_head

    next = addr
    while (count < maxel):
        next = readPtr(next + offset)
        if (next == 0 or next == addr):
            break
        count += 1
    return count

#     ======= read from global according to its type  =========


def readSymbol(symbol, art = None):
    vi = whatis(symbol)
    return vi.reader(vi.addr)
    



# Get sizeof(type)
def getSizeOf(vtype):
    return struct_size(vtype)

# .........................................................................
import time


# 8K - pages
shift = 12
psize = 1 << shift
_page_cache = {}


# Flush cache (for tools running on a live system)
def flushCache():
    _page_cache.clear()
    
# ..............................................................
    
# Get a list of non-empty bucket addrs (ppointers) from a hashtable.
# A hashtable here is is an array of buckets, each one is a structure
# with a pointer to next structure. On 2.6 'struct hlist_head' is used
# but we don't depend on that, we just need to know the offset of the
# 'chain' (a.k.a. 'next') in our structure
#
# start - address of the 1st hlist_head
# bsize - the size of a structure embedding hlist_head
# items - a dimension of hash-array
# chain_off - an offset of 'hlist_head' in a bucket
def getFullBuckets(start, bsize, items, chain_off=0):
    chain_sz = pointersize
    m = readmem(start, bsize * items)
    buckets = []
    for i in xrange(0, items):
       chain_s = i*bsize + chain_off
       s = m[chain_s:chain_s+chain_sz]
       bucket = mem2long(s)
       #bucket = mem2long(m, chain_sz, chain_s, False)
       if (bucket != 0):
           #print i
           buckets.append(bucket)
    del m
    return buckets

# Traverse list_head linked lists


def getStructInfo(stype):
    si = SUInfo(stype)
    return si



def whatis(symbol, art = None):
    try:
        e = crash.gdb_whatis(symbol)
    except crash.error:
        raise TypeError, "There's no symbol <%s>" % symbol

    # Return Varinfo
    vi = VarInfo(e["fname"])
    ti = TypeInfo('', False)
    update_TI(ti, e)
    vi.ti = ti
    vi.addr = sym2addr(symbol)

    # This is for backwards compatibility only, will be obsoleted
    vi.ctype = ti.stype
    return vi

    
    


# Check whether our basetype is really a typedef. We need this to understand how
# to generate 'smarttype'. E.g. for __u32 we'll find that this is an unsigned integer
# For typedefs to pointers we'll know that this is really a pointer type and should
# be treated as such.
# Possible return values:
#           None    - this is not a typedef, not transformation possible
#           Int     - this is a signed Integer type
#           Uint    - this is a Unsigned integer type
#           Ptr     - this is a pointer, do not try to do anything else
#           SUPtr   - this is a pointer to SU
#           String  - this is a pointer to Char

def isTypedef(basetype):
    return None



#
#
#  -- emulating low-level functions that can be later replaced by
#  Python extension to crash
#
#
# {"symbol_exists",  py_crash_symbol_exists, METH_VARARGS},
# {"struct_size",  py_crash_struct_size, METH_VARARGS},
# {"union_size",  py_crash_union_size, METH_VARARGS},
# {"member_offset",  py_crash_member_offset, METH_VARARGS},
# {"member_size",  py_crash_member_size, METH_VARARGS},
# {"get_symbol_type",  py_crash_get_symbol_type, METH_VARARGS},


# Return -1 if the struct is unknown
def struct_size(sname):
    try:
        si = TypeInfo(sname)
        return si.size
    except:
        return -1

def struct_exists(sname):
    if (struct_size(sname) == -1):
        return False
    else:
        return True
    
def member_size(sname, fname):
    #print "++member_size", sname, fname
    sz = -1
    try:
        ti = getStructInfo(sname)[fname].ti
        sz = ti.size * ti.elements
    except KeyError:
        pass
    return sz


# Find a member offset. If field name contains a dot, we do our
# best trying to find its offset checking intermediate structures as
# needed

def member_offset(sname, fname):
    try:
        si = getStructInfo(sname)
        if (fname.find('.') == -1):
            return si[fname].offset
        else:
            # We have dots in field name, try to walk the structures
            return -1                   # Not done yet
    except:
        return -1

    


# A cached version
__cache_symbolexists = {}
def symbol_exists(sym):
    try:
        return  __cache_symbolexists[sym]
    except:
        rc = noncached_symbol_exists(sym)
        __cache_symbolexists[sym] = rc
        return rc
    


# Aliases
union_size = struct_size


import crash
from crash import sym2addr, addr2sym
from crash import  mem2long, FD_ISSET
def exec_gdb_command(cmd):
    return crash.get_GDB_output(cmd).replace('\r', '')

noncached_symbol_exists = crash.symbol_exists
exec_crash_command = crash.exec_crash_command
exec_gdb_command = crash.get_GDB_output
getFullBuckets = crash.getFullBuckets
readPtr = crash.readPtr
sLong = crash.sLong
le32_to_cpu = crash.le32_to_cpu
le16_to_cpu = crash.le16_to_cpu
cpu_to_le32 = crash.cpu_to_le32
uvtop = crash.uvtop
getListSize = crash.getListSize
# For some reason the next line runs slower than GDB version
#GDB_sizeof = crash.struct_size
readmem = crash.readmem
nc_member_offset = crash.member_offset


def print_stats():
    print "count_cached_attr=%d (%d)" % (count_cached_attr, count_total_attr)
