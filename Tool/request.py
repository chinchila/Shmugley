import os
import ssl
import time
import debug
import socket
import random
import string
from urllib.parse import urlparse

MODES_TECL = 0
MODES_CLTE = 1
MODES_TETE = 0

class SSL():
    def __init__( self, buffer_size=4096 ):
        self.buffer_size = buffer_size
        self.connected = False

    def connect( self, host, port=443, timeout=20 ):
        self.context = ssl.SSLContext( ssl.PROTOCOL_TLSv1_2 )
        socket.setdefaulttimeout( timeout )
        self.socket = socket.create_connection( ( host, port ) )
        self.ssl = self.context.wrap_socket( self.socket, server_hostname=host )
        self.ssl.settimeout( timeout )
        self.connected = True

    def close( self ):
        self.ssl.close()
        self.connected = False
        del self.ssl, self.context, self.socket

    def is_connected( self ):
        return self.connected

    def send( self, d ):
        return self.ssl.send( d )

    def recv( self, timeout=20 ):
        try:
            self.ssl.settimeout( timeout )
            ret = self.ssl.recv( self.buffer_size )
        except Exception as exc:
            ret = None
            # self.close()
            self.connected = False
            debug.error( exc )
        return ret

class WebSocket():
    def __init__( self, buffer_size=4096 ):
        self.buffer_size = buffer_size
        self.connected = False

    def connect( self, host, port=80, timeout=20 ):
        socket.setdefaulttimeout( timeout )
        self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
        self.socket.settimeout( timeout )
        self.socket.connect( ( host, port ) )
        self.connected = True

    def close( self ):
        self.socket.close()
        self.socket.shutdown( socket.SHUT_RDWR )
        self.connected = False
        del self.socket

    def is_connected( self ):
        return self.connected

    def send( self, d ):
        self.socket.send( d )

    def recv( self, timeout=20 ):
        try:
            self.socket.settimeout( timeout )
            ret = self.socket.recv( self.buffer_size )
        except Exception as exc:
            ret = None
            # self.close()
            self.connected = False
            debug.error( exc )
        return ret

def random_string( N=3 ):
    st = ''.join( random.choices( string.ascii_lowercase, k=N ) )
    return st.encode()

def append_end( buffer, crlf, buffer_mode ):
    if buffer_mode:
        if not buffer.endswith(CRLF_TOKEN + CRLF_TOKEN):
            if buffer.endswith(CRLF_TOKEN):
                buffer += CRLF_TOKEN
            else:
                buffer += CRLF_TOKEN + CRLF_TOKEN
    else:
        if not buffer.endswith(crlf + crlf):
            if buffer.endswith(crlf):
                buffer += crlf
            else:
                buffer += crlf + crlf
    return buffer

TECL_TEMPLATE = """{method} {path} HTTP/1.1{crlf}
Host: {hostname}{crlf}
User-Agent: {agent}{crlf}
Content-Length: {length}{crlf}
Transfer-Encoding: {encoding}{crlf}
{headers}
{crlf}
{requests}
0{crlf}
{crlf}
"""

CLTE_TEMPLATE = """
{method} {path} HTTP/1.1{crlf}
Host: {hostname}{crlf}
User-Agent: {agent}{crlf}
Content-Length: {length}{crlf}
Transfer-Encoding: {encoding}{crlf}
{headers}
{crlf}
0{crlf}
{crlf}
{requests}
"""

TECL_TEMPLATE = TECL_TEMPLATE.replace( "\n", "" )
CLTE_TEMPLATE = CLTE_TEMPLATE.replace( "\n", "" )

CRLF_TOKEN  = b"|CRLF|"
RAND_TOKEN  = b"|RAND|"
CL_TOKEN    = b"|CL|"
PL_TOKEN    = b"|PL|"

class Request():
    def __init__( self, url, crlf, mode=0, timeout=20 ):
        self.timeout = timeout
        self.crlf = crlf
        self.mode = mode
        self.length = 0
        self.url = urlparse( url )
        self.buffer = b""
        self.agent = "Shmugley"
        self.requests = []
        self.buffer_mode = False
        if self.url.scheme == "http":
            self.socket = WebSocket()
        elif self.url.scheme == "https":
            self.socket = SSL()
        else:
            debug.error( "Scheme can only be http or https." )

    def parse_headers( self, headers ):
        ret_headers = b""
        if headers is not None:
            for header in headers:
                ret_headers += b"%b%b"%(header.encode(), self.crlf)
        return ret_headers

    @classmethod
    def from_buffer( cls, url, crlf, mode, buffer ):
        r = Request( url, crlf )
        r.buffer = buffer
        r.mode = mode
        r.buffer_mode = True
        return r

    def show( self ):
        return self.buffer.decode()
    
    def append_end( self ):
        self.buffer = append_end( self.buffer, self.crlf, self.buffer_mode )

    def align( self, path ):
        self.append_end()
        align = b"GET %b HTTP/1.1%bHost: %b%b"%(path.encode(), self.crlf, self.url.netloc.encode(), self.crlf)
        self.buffer += align

    def setup_connection( self ):
        if not self.socket.is_connected():
            loc = self.url.netloc.split( ":" )
            if len(loc) > 1:
                self.socket.connect( loc[0], int( loc[1] ), self.timeout )
            else:
                self.socket.connect( loc[0], timeout=self.timeout )

    def close( self ):
        if(self.socket.is_connected()):
            self.socket.close()

    def start( self, payload ):
        self.setup_connection()
        self.append_end()
        self.replace( payload )
        self.socket.send( self.buffer )
        res = []
        while True:
            try:
                result = self.recv_web()
                if( result[0] == True and result[1] == "" ): break
                if( result[1] != "" ): res.append( result )
            except:
                break
        return res
    
    def search_code(self, path, headers, method ):
        self.setup_connection()
        headers_buf = self.parse_headers( headers )
        if path == b"404":
            lastpath = b"/" + random_string()
            buf = b"%b %b HTTP/1.1%bHost: %b%b"%(method.encode(), lastpath, self.crlf, self.url.netloc.encode(), self.crlf)
            buf += headers_buf
            buf = append_end( buf, self.crlf, self.buffer_mode )
            self.socket.send( buf )
            res = self.recv_web()
            while "404 NOT FOUND" not in res[1]:
                lastpath = b"/" + random_string()
                buf = b"%b %b HTTP/1.1%b"%(method.encode(), lastpath, self.crlf)
                buf += headers_buf
                self.socket.send( buf )
                res = self.recv_web()
            return lastpath

    def replace(self, payload):
        self.buffer = self.buffer.replace(CRLF_TOKEN, self.crlf)
        self.buffer = self.buffer.replace(RAND_TOKEN, bytearray(os.urandom(5)))
        self.buffer = self.buffer.replace(PL_TOKEN, payload)

    def append_request( self, path, headers, method, req_number ):
        mypath = path.encode()
        if mypath == b"": mypath = b"/"
        if mypath[0] != ord( "/" ):
            mypath = self.search_code( mypath, headers, method )
        else:
            headers = self.parse_headers( headers )
            buf = b"%b %b HTTP/1.1%b"%(method.encode(), mypath, self.crlf)
            buf += headers + self.crlf
        if req_number != 1:
            req_size = hex(len(buf))[2:].encode()
            self.requests.append((req_size, buf))
        else:
            self.method = method.encode()
            self.path = mypath
            self.headers = self.parse_headers(headers)

    def end( self ):
        buf = b""
        for r in self.requests:
            if self.mode == MODES_TECL:
                buf += r[0] + self.crlf
            buf += r[1]
        buf += self.crlf
        if not self.buffer_mode:
            leng = 1
            if len(self.requests) > 0:
                leng = str(len(self.requests[0][0]) + len(self.crlf))
            if self.mode == MODES_TECL:
                self.buffer = TECL_TEMPLATE.format(
                    method=self.method.decode(),
                    path=self.path.decode(),
                    crlf=self.crlf.decode(),
                    hostname=self.url.netloc,
                    agent=self.agent,
                    length=leng,
                    encoding="|PL|",
                    headers=self.headers.decode(),
                    requests=buf.decode()
                ).encode()
            elif self.mode == MODES_CLTE:
                self.buffer = CLTE_TEMPLATE.format(
                    method=self.method.decode(),
                    path=self.path.decode(),
                    crlf=self.crlf.decode(),
                    hostname=self.url.netloc,
                    agent=self.agent,
                    length=len(buf)+buf.count(self.crlf)-3,
                    encoding="|PL|",
                    headers=self.headers.decode(),
                    requests=buf.decode()
                ).encode()

# This function has this license, from https://github.com/defparam/smuggler
# MIT License

# Copyright (c) 2020 Evan Custodio

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
    def recv_web( self ):
        ST_PROCESS_HEADERS = 0
        ST_PROCESS_BODY_CL = 1
        ST_PROCESS_BODY_TE = 2
        ST_PROCESS_BODY_NODATA = 3
    
        state = ST_PROCESS_HEADERS
        dat_raw = b""
        CL_TE = -1
        size = 0
        cls = False
        http_ver = "1.1"
        while True:
            retry = 0
            while True:
                sample = self.socket.recv( 1 )
                if ((sample == None) or (sample == b"")):
                    if (retry == 5):
                        if len(dat_raw) == 0:
                            cls = True
                        return (cls, dat_raw.decode("UTF-8",'ignore'))
                    retry += 1
                else:
                    dat_raw += sample
                    break
                    
            dat_dec = dat_raw.decode("UTF-8",'ignore')
            dat_split = dat_dec.split("\r\n")
            
            if (state == ST_PROCESS_HEADERS):
                if dat_split[0][0:4] == "HTTP":
                    http_ver = dat_split[0][5:8]
                    if (http_ver == "1.0"):
                        cls = True
                    state = ST_PROCESS_HEADERS
                    for line in dat_split:
                        if (len(line) >= len("Transfer-Encoding:")) and (line[0:18].lower() == "transfer-encoding:"):
                            CL_TE = 1
                        elif (len(line) >= len("Content-Length:")) and (line[0:15].lower() == "content-length:"):
                            size = int(line[15:].strip())
                            CL_TE = 0
                        elif (len(line) >= len("Connection: close")) and (line[0:17].lower() == "connection: close"):
                            cls = True
                        elif (len(line) >= len("Connection: keep-alive")) and (line[0:22] == "connection: keep-alive"):
                            cls = False
                        elif (line == ""):
                            if (CL_TE == 0):
                                state = ST_PROCESS_BODY_CL
                            elif (CL_TE == 1):
                                state = ST_PROCESS_BODY_TE
                            else:
                                state = ST_PROCESS_BODY_NODATA
                                return (cls, dat_dec)
                            break
                        
            if (state == ST_PROCESS_BODY_CL):
                start = dat_dec.find( "\r\n\r\n" )+4
                if (len(dat_raw)-start) == size:
                    return (cls, dat_dec)
            
            if (state == ST_PROCESS_BODY_TE):
                start = dat_raw.find( b"\r\n\r\n" )+4
                body = dat_raw[start:]
                finished = True
                nxt = 0
                while True:
                    nxt = body.find(b"\r\n")+2
                    szchunk_st = body[:nxt-2]
                    if szchunk_st == b"":
                        finished = False
                        break
                    szchunk = int(szchunk_st, 16)
                    if szchunk == 0: break
                    body = body[nxt:]
                    if len( body[:szchunk] ) != szchunk:
                        finished = False
                        break
                    else:
                        body = body[szchunk+2:]
                if finished:
                    return (cls, dat_dec)
