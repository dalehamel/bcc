#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# mctop   Memcached key operation analysis tool
#         For Linux, uses BCC, eBPF.
#
# USAGE: mctop.py  -p PID
#
# This uses in-kernel eBPF maps to trace and analyze key access rates and
# objects. This can help to spot hot keys, and tune memcached usage for
# performance.
#
# Copyright 2019 Shopify, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 20-Nov-2019   Dale Hamel   Created this.
# Inspired by the ruby tool of the same name by Marcus Barczak in 2012, see
# see also https://github.com/etsy/mctop
# see also https://github.com/tumblr/memkeys

from __future__ import print_function
from time import sleep, strftime, monotonic
from bcc import BPF, USDT, utils
from subprocess import call
from math import floor
from enum import Enum
import argparse
import sys
import select
import tty
import termios
import json

# FIXME refactor globals into class vars or explicit global singleton classes

class McCommand(Enum):
   GET = 1
   ADD = 2
   SET = 3
   REPLACE = 4
   PREPEND = 5
   APPEND = 6
   TOUCH = 7
   CAS = 8
   INCR = 9
   DECR = 10
   DELETE = 11

# FIXME better help
# arguments
examples = """examples:
    ./mctop -p PID          # memcached usage top, 1 second refresh
"""

supported_commands = [McCommand.GET, McCommand.ADD, McCommand.SET,
                      McCommand.REPLACE, McCommand.PREPEND,
                      McCommand.APPEND, McCommand.TOUCH, McCommand.CAS,
                      McCommand.INCR, McCommand.DECR, McCommand.DELETE]
parser = argparse.ArgumentParser(
    description="Memcached top key analysis",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, help="process id to attach to")
parser.add_argument(
    "-o",
    "--output",
    action="store",
    help="save map data to /tmp/OUTPUT.json if 'W' is issued to dump the map")

parser.add_argument("-C", "--noclear", action="store_true", # Implies --no-footer?
                    help="don't clear the screen")
parser.add_argument("-r", "--maxrows", default=20,
                    help="maximum rows to print, default 20")
parser.add_argument('-c','--commands', action='append', default=[],
                    choices=[ cmd.name for cmd in supported_commands],
                    help="Command to trace, can specify many. Default is all." )
parser.add_argument("interval", nargs="?", default=1,
                    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
                    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
                    help=argparse.SUPPRESS)
parser.add_argument("--debug", action="store_true",
                    help="Enable printk debugging for eBPF probes")


# FIXME clean this up
args = parser.parse_args()
traced_commands = args.commands
if len(traced_commands) == 0:
    traced_commands=[cmd.name for cmd in supported_commands]

interval = int(args.interval)
countdown = int(args.count)
maxrows = int(args.maxrows)
clear = not int(args.noclear) # FIXME ensure it still works with clear disabled
outfile = args.output
pid = args.pid

# Globals
exiting = 0
sort_mode = "C"  # FIXME allow specifying at runtime
selected_line = 0
selected_page = 0
selected_key  = ""
start_time    = 0
sort_ascending = True
view_mode = 1 # 1 - index
match_key = None
bpf = None
sorted_output = []

SELECTED_LINE_UP = 1
SELECTED_LINE_DOWN = -1
SELECTED_LINE_PAGE_UP = maxrows * -1
SELECTED_LINE_PAGE_DOWN = maxrows
SELECTED_LINE_START = "start"
SELECTED_LINE_END = "end"

sort_modes = {
    "C": "calls", # total calls to key
    "S": "size",  # latest size of key
    "R": "req/s", # requests per second to this key
    "B": "bw",    # total bytes accesses on this key
    "L": "lat"    # aggregate call latency for this key
}

commands = {
    "T": "tgl",  # toggle sorting by ascending / descending order
    "W": "dmp",  # clear eBPF maps and dump to disk (if set)
    "Q": "quit"  # exit mctop
}
# FIXME have helper to generate per  type?
# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

#define READ_MASK 115
struct keyhit_t {
    char keystr[READ_MASK];
};

struct value_t {
    u64 count;
    u64 bytecount;
    u64 totalbytes;
    u64 keysize;
    u64 timestamp;
    u64 latency;
};

DEFINE_BPF_PRINTK_DEBUG
DEFINE_MC_COMMAND_ENUM

BPF_HASH(keyhits, struct keyhit_t, struct value_t);
BPF_HASH(comm_start, int32_t, u64);
BPF_HASH(lastkey, u64, struct keyhit_t);
BPF_HASH(calls_traced, u64, u64);
BPF_HASH(processed_commands, u64, u64);

int trace_command_start(struct pt_regs *ctx) {
    int32_t conn_id = 0;
    bpf_usdt_readarg(1, ctx, &conn_id);
    u64 nsec = bpf_ktime_get_ns();
    comm_start.update(&conn_id, &nsec);
    return 0;
}

int trace_command_end(struct pt_regs *ctx) {
    struct keyhit_t key = {};
    struct keyhit_t *key_raw;
    struct value_t *valp;
    int32_t conn_id = 0;
    u64 lastkey_id = 0;
    u64 nsec = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &conn_id);

    u64 *start = comm_start.lookup(&conn_id);

    if (start != NULL) {
        u64 call_lat = nsec - *start;
        key_raw = lastkey.lookup(&lastkey_id);
        if (key_raw != NULL ) {
          __builtin_memcpy(&key.keystr, key_raw->keystr, sizeof(key.keystr));
#ifdef BPF_PRINTK_DEBUG
          bpf_trace_printk("LAST KEY: %s\\n", key_raw->keystr);
#endif
          valp = keyhits.lookup(&key);
          if (valp != NULL) {
              processed_commands.increment(lastkey_id);
              valp->latency += call_lat;
          }
        }
    }
    return 0;
}
"""

trace_command_ebpf = """
int trace_command_COMMAND_NAME(struct pt_regs *ctx) {
    u64 keystr = 0;
    int32_t bytecount = 0; // type is -4@%eax in stap notes, which is int32
    uint8_t keysize = 0; // type is 1@%cl, which should be uint8
    struct keyhit_t keyhit = {0};
    struct value_t *valp, zero = {};

    // GET and TOUCH selected because they sometimes use 64 bit int for keysize
    if ((COMMAND_ENUM_ID == MC_CMD_GET) ||
        (COMMAND_ENUM_ID == MC_CMD_TOUCH)) {
        bpf_usdt_readarg(3, ctx, &keysize);
        if (keysize == 0) {
            // GET command is annoying and has both int64 and int8 signatures
            u64 widekey = 0; // type on get command is 8@-32(%rbp), should be u64
            bpf_usdt_readarg(3, ctx, &widekey);
            keysize = widekey;
        }
    }
    else {
        bpf_usdt_readarg(3, ctx, &keysize);
    }

    bpf_usdt_readarg(2, ctx, &keystr);

    if (COMMAND_ENUM_ID != MC_CMD_DELETE)
        bpf_usdt_readarg(4, ctx, &bytecount);

    // see https://github.com/memcached/memcached/issues/576
    // ideally per https://github.com/iovisor/bcc/issues/1260 we should be able to
    // read just the size we need, but this doesn't seem possible and throws a
    // verifier error
    bpf_probe_read(&keyhit.keystr, sizeof(keyhit.keystr), (void *)keystr);

    valp = keyhits.lookup_or_init(&keyhit, &zero);
    valp->count++;
    valp->keysize = keysize;
    valp->timestamp = bpf_ktime_get_ns();

    u64 lastkey_id = 0;
    lastkey.update(&lastkey_id, &keyhit);
    calls_traced.increment(lastkey_id);

    if (bytecount > 0) {
        valp->bytecount = bytecount;
        valp->totalbytes += bytecount;
    }

    return 0;
}
"""

# Since it is possible that we read the keys incorrectly, we need to fix the
# hash keys and combine their values intelligently here, producing a new hash
# see https://github.com/memcached/memcached/issues/576
# A possible solution may be in flagging to the verifier that the size given
# by a usdt argument is less than the buffer size,
# see https://github.com/iovisor/bcc/issues/1260#issuecomment-406365168
def reconcile_keys(bpf_map):
  new_map = {}

  for k,v in bpf_map.items():
      shortkey = k.keystr[:v.keysize].decode('utf-8', 'replace')
      if shortkey in new_map:

          # Sum counts on key collision
          new_map[shortkey]['count'] += v.count
          new_map[shortkey]['totalbytes'] += v.totalbytes
          new_map[shortkey]['latency'] += v.latency

          # If there is a key collision, take the data for the latest one
          if v.timestamp > new_map[shortkey]['timestamp']:
              new_map[shortkey]['bytecount'] = v.bytecount
              new_map[shortkey]['timestamp'] = v.timestamp
      else:
          new_map[shortkey] = {
              "count": v.count,
              "bytecount": v.bytecount,
              "totalbytes": v.totalbytes,
              "timestamp": v.timestamp,
              "latency": v.latency,
          }
  return new_map

def sort_output(unsorted_map):
    global sort_mode
    global sort_ascending

    output = unsorted_map
    if sort_mode == "C":
        output = sorted(output.items(), key=lambda x: x[1]['count'])
    elif sort_mode == "S":
        output = sorted(output.items(), key=lambda x: x[1]['bytecount'])
    elif sort_mode == "R":
        output = sorted(output.items(), key=lambda x: x[1]['cps'])
    elif sort_mode == "B":
        output = sorted(output.items(), key=lambda x: x[1]['bandwidth'])
    elif sort_mode == "L":
        output = sorted(output.items(), key=lambda x: x[1]['call_lat'])

    if sort_ascending:
        output = reversed(output)

    return list(output)

# Set stdin to non-blocking reads so we can poll for chars

def update_selected_key():
    global selected_key
    global selected_line

    if len(sorted_output) > 0 and selected_line < len(sorted_output) and len(sorted_output[selected_line]) > 0:
        selected_key = sorted_output[selected_line][0]

def change_selected_line(direction):
    global selected_line
    global selected_page
    global sorted_output
    global maxrows

    if direction == SELECTED_LINE_START:
        selected_line = 0
        selected_page = 0
        update_selected_key()
        return
    elif direction == SELECTED_LINE_END:
        selected_line = len(sorted_output) -1
        selected_page = floor(selected_line / maxrows)
        update_selected_key()
        return

    if direction > 0 and (selected_line + direction) >= len(sorted_output):
        if len(sorted_output) > 0:
            selected_line = len(sorted_output) - 1
        else:
            selected_line = 0
    elif direction < 0 and (selected_line + direction) <= 0:
        selected_line = 0
        selected_page = 0
    else:
        selected_line += direction
        selected_page = floor(selected_line / maxrows)

    update_selected_key()

def readKey(interval):
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(sys.stdin.fileno())
        new_settings = termios.tcgetattr(fd)
        new_settings[3] = new_settings[3] & ~(termios.ECHO | termios.ICANON)
        if select.select([sys.stdin], [], [], interval) == ([sys.stdin], [], []):
            key = sys.stdin.read(1)
            global sort_mode

            if key.lower() == 't':
                global sort_ascending
                sort_ascending = not sort_ascending
            elif key == 'C':
                sort_mode = 'C'
            elif key == 'S':
                sort_mode = 'S' # FIXME make lowercase s 'select' to select key
            elif key == 'R':
                sort_mode = 'R'
            elif key == 'B':
                sort_mode = 'B'
            elif key == 'L':
                sort_mode = 'L'
            elif key.lower() == 'j':
                change_selected_line(SELECTED_LINE_UP)
            elif key.lower() == 'k':
                change_selected_line(SELECTED_LINE_DOWN)
            elif key.lower() == 'h': # Reserved for shifting print of key
                pass
                #ROTATE_KEY_LEFT
            elif key.lower() == 'l': # Reserved for shifting print of key
                pass
                #ROTATE_KEY_RIGHT
            elif key.lower() == 'u':
                change_selected_line(SELECTED_LINE_PAGE_UP)
            elif key.lower() == 'd':
                change_selected_line(SELECTED_LINE_PAGE_DOWN)
            elif key == 'g':
                change_selected_line(SELECTED_LINE_START)
            elif key == 'G':
                change_selected_line(SELECTED_LINE_END)
            elif key.lower() == 'w':
                 dump_map()
            elif key.lower() == 'q':
                print("QUITTING")
                global exiting
                exiting = 1
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


# FIXME this should dump a full representation of the eBPF data in a reasonable
# schema
def dump_map():
    global outfile
    global bpf
    global sorted_output
    global selected_line
    global selected_page

    if outfile is not None:
        out = open('/tmp/%s.json' % outfile, 'w')
        json_str = json.dumps(sorted_output)
        out.write(json_str)
        out.close

    # FIXME null check?
    bpf.get_table("keyhits").clear() # FIXME clear other maps
    sorted_output.clear()
    selected_line = 0
    selected_page = 0

# FIXME build from probe definition?
def build_probes(render_only):
    global pid
    global args
    global usdt
    global bpf_text
    global start_time
    global traced_commands
    global trace_command_ebpf
    rendered_text = bpf_text

    for _, val in enumerate(traced_commands):
        rendered_text += "\n" + trace_command_ebpf.replace('COMMAND_NAME',
                                                             val.lower())\
                                                  .replace('COMMAND_ENUM_ID',
                                                            "MC_CMD_%s"%(val))


    enum_text = "\n".join(["#define MC_CMD_%s %d" % (cmd.name, cmd.value) for cmd in McCommand])
    rendered_text = rendered_text.replace('DEFINE_MC_COMMAND_ENUM', enum_text)
    rendered_text = rendered_text.replace('DEFINE_BPF_PRINTK_DEBUG', '#define BPF_PRINTK_DEBUG 1' if args.debug else "")

    if render_only:
        print(rendered_text)
        exit()

    usdt = USDT(pid=pid)
    # FIXME use fully specified version, port this to python

    for _, val in enumerate(traced_commands):
        usdt.enable_probe(probe="command__%s" % (val.lower()),
                              fn_name="trace_command_%s" % (val.lower()))
    usdt.enable_probe(probe="process__command__start",
                                            fn_name="trace_command_start")
    usdt.enable_probe(probe="process__command__end",
                                            fn_name="trace_command_end")
    bpf = BPF(text=rendered_text, usdt_contexts=[usdt])
    start_time = bpf.monotonic_time()
    return bpf

def teardown_bpf():
    global bpf
    if bpf != None:
        dump_map()
        bpf.cleanup()
        del bpf

def bpf_init(dump_ebpf):
    global match_key
    global bpf
    teardown_bpf() # FIXME - avoid tearing down until a new match_key is selected?
    match_key = None
    bpf = build_probes(dump_ebpf)

def print_keylist():
    global bpf
    global maxrows
    global sorted_output
    global start_time
    global selected_key

    # FIXME better calculate the key width so that it can be shifted with h/l
    print("%-30s %8s %8s %8s %8s %8s" % ("MEMCACHED KEY", "CALLS",
                                         "OBJSIZE", "REQ/S",
                                         "BW(kbps)", "LAT(MS)"))
    keyhits_raw = bpf.get_table("keyhits") # Workaround for older kernels
    keyhits = reconcile_keys(keyhits_raw)
    interval = (bpf.monotonic_time() - start_time) / 1000000000

    data_map = {}
    for k, v in keyhits.items():
        data_map[k] = {
            "count": v["count"],
            "bytecount": v["bytecount"],
            "totalbytes": v["totalbytes"],
            "timestamp": v["timestamp"],
            "cps": v["count"] / interval,
            "bandwidth": (v["totalbytes"] / 1000) /interval if v["totalbytes"] > 0 else 0,
            "latency": v["latency"],
            "call_lat": (v["latency"] / v["count"]) / 1000,
        }

    sorted_output = sort_output(data_map)

    max_pages = floor(len(sorted_output) / maxrows)

    printed_lines = 0
    for i, tup in enumerate(sorted_output):  # FIXME sort this
        global selected_line
        global selected_page

        k = tup[0]
        v = tup[1]
        fmt_start = ""
        fmt_end   = ""

        page = floor(int(i) / int(maxrows))

        if page != selected_page:
            continue

        if i == selected_line:
            fmt_start = "\033[1;30;47m" # White background, black text
            fmt_end   = "\033[1;0;0;0m"

        print("%s%-30s %8d %8d %8.2f %8.2f %8.2f%s" % (fmt_start, k, v['count'], v['bytecount'],
                                             v['cps'], v['bandwidth'],
                                             v['call_lat'], fmt_end) )
        printed_lines += 1

        if printed_lines >= maxrows:
            break

    print((maxrows - printed_lines) * "\r\n")
    #calls_traced = bpf["calls_traced"].values()[0].value if len(bpf["calls_traced"].values()) > 0 else 0
    #processed_commands= bpf["processed_commands"].values()[0].value if len(bpf["processed_commands"].values()) > 0 else 0
    #print("[%d / %d]" % (calls_traced, processed_commands) )
    sys.stdout.write("[Curr: %s/%s Opt: %s:%s|%s:%s|%s:%s|%s:%s|%s:%s]" %
                     (sort_mode,
                      "Asc" if sort_ascending else "Dsc",
                      'C', sort_modes['C'],
                      'S', sort_modes['S'],
                      'R', sort_modes['R'],
                      'B', sort_modes['B'],
                      'L', sort_modes['L']
                      ))

    sys.stdout.write("[%s:%s %s:%s %s:%s](%d/%d)" % (
        'T', commands['T'],
        'W', commands['W'],
        'Q', commands['Q'],
        selected_page + 1,
        max_pages + 1
    ))

def run():
    global args
    global exiting
    global bpf
    global start_time
    global view_mode
    global interval

    bpf_init(args.ebpf)
    first_loop = True

    start_time = bpf.monotonic_time()

    while True:
        try:
            if not first_loop:
                readKey(interval)
            else:
                first_loop = False
        except KeyboardInterrupt:
            exiting = 1

        # header
        if clear:
            print("\033c", end="")

        if view_mode == 1:
            print_keylist()

        print("\033[%d;%dH" % (0, 0))

        if exiting:
            print("\033c", end="")
            exit()
run()
