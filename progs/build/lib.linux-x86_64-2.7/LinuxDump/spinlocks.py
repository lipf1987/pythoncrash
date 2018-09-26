# -*- coding: utf-8 -*-
#
# Interpreting spinlock structures
#

# Copyright (C) 2012 Alex Sidorenko <asid@hp.com>
# Copyright (C) 2012 Hewlett-Packard Co., All rights reserved.


# To facilitate migration to Python-3, we start from using future statements/builtins
from __future__ import print_function


from pykdump.API import *

__TICKET_SHIFT = 16

def ticket_spin_is_locked(lock):
    tmp = lock.slock
    return (((tmp >> __TICKET_SHIFT) ^ tmp) & ((1 << __TICKET_SHIFT) - 1))

spin_is_locked = ticket_spin_is_locked