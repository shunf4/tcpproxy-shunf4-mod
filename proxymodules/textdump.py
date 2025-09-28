#!/usr/bin/env python3
import os.path as path
import re
import datetime
from codecs import decode, lookup

HOSTNAME_INVALID_PATTERN = re.compile("[^a-zA-Z0-9._-]")
class Module:
    def __init__(self, incoming=False, verbose=False, options=None):
        # extract the file name from __file__. __file__ is proxymodules/name.py
        self.name = path.splitext(path.basename(__file__))[0]
        self.description = 'Simply print the received data as text'
        self.incoming = incoming  # incoming means module is on -im chain
        self.find = None  # if find is not None, this text will be highlighted
        self.source = ("NO_SOURCE", "")
        self.destination = ("NO_DEST", "")
        self.logdir = None
        self.contexts = {}
        # self.codec = 'latin_1'
        self.codec = 'utf-8'
        if options is not None:
            if 'find' in options.keys():
                self.find = bytes(options['find'], 'ascii')  # text to highlight
            if 'color' in options.keys():
                self.color = bytes('\033[' + options['color'] + 'm', 'ascii')  # highlight color
            else:
                self.color = b'\033[31;1m'
            if 'codec' in options.keys():
                codec = options['codec']
                try:
                    lookup(codec)
                    self.codec = codec
                except LookupError:
                    print(f"{self.name}: {options['codec']} is not a valid codec, using {self.codec}")
            log_dir = str(options.get("logdir", ""))
            if log_dir != "":
                self.logdir = log_dir

    def create_context(self, timestamp):
        ctx = {}
        self.contexts[timestamp] = ctx
        ctx["remote_hostname"] = None
        ctx["timestamp"] = None
        ctx["timestamp_str"] = None
        ctx["source"] = None
        ctx["destination"] = None

        return ctx
        
    def help(self):
        return """
        \tfind: string that should be highlighted\n
        \tcolor: ANSI color code. Will be wrapped with \\033[ and m, so\n
         passing 32;1 will result in \\033[32;1m (bright green)
        \tcodec: codec to decode bytes to string (default utf-8)\n
        \tlogdir: if not set, output to stdout; else output to log files under logdir\n"""
    
    def get_destination(self, timestamp):
        return self.contexts.get(timestamp, {}).get("destination") or self.destination

    def get_source(self, timestamp):
        return self.contexts.get(timestamp, {}).get("source") or self.source

    def decide_log_filename(self, timestamp):
        ctx = self.contexts[timestamp]
        remote = self.get_source(timestamp) if self.incoming else self.get_destination(timestamp)
        remote_addr = ctx["remote_hostname"] or remote[0]
        remote_port = remote[1]
        remote_addr = HOSTNAME_INVALID_PATTERN.sub("_", str(remote_addr))
        if ctx["timestamp_str"] is None:
            ctx["timestamp_str"] = ctx["timestamp"].strftime("%Y-%m-%d_%H-%M-%S-%f")
        filename = "%s$$%s_%d_text.log" % (ctx["timestamp_str"], remote_addr, remote_port)
        return filename
        
    def mhandle_close(self, timestamp):
        if self.logdir:
            with open(path.join(self.logdir, self.decide_log_filename(timestamp)), "ab") as f:
                f.write(("<<<<<<<<<<< RCLOSE <<<<<<<<<<<\n" if self.incoming else ">>>>>>>>>>> LCLOSE >>>>>>>>>>>\n").encode("ascii"))
                f.write("\n".encode("ascii"))
        else:
            print(("<<<<<<<<<<< RCLOSE <<<<<<<<<<<" if self.incoming else ">>>>>>>>>>> LCLOSE >>>>>>>>>>>"))

    def execute_ex(self, data, timestamp):
        to_print = ""
        to_print_b = b''
        if self.find is None:
            to_print_b = data
        else:
            pdata = data.replace(self.find, self.color + self.find + b'\033[0m')
            to_print_b = pdata
        to_print = decode(to_print_b, self.codec, errors='ignore')
            
        if self.logdir:
            with open(path.join(self.logdir, self.decide_log_filename(timestamp)), "ab") as f:
                f.write(("<<<<<<<<<<< RECV <<<<<<<<<<<\n" if self.incoming else ">>>>>>>>>>> SEND >>>>>>>>>>>\n").encode("ascii"))
                f.write(to_print_b)
                f.write("\n".encode("ascii"))
        else:
            print(("<<<<<<<<<<< RECV <<<<<<<<<<<" if self.incoming else ">>>>>>>>>>> SEND >>>>>>>>>>>"))
            print(to_print)
            
        return data


if __name__ == '__main__':
    print('This module is not supposed to be executed alone!')
