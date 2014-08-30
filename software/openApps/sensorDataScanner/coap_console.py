import os
import sys
import time
import json
import cmd

p = os.path.dirname(sys.argv[0])
p = os.path.join(p,'..','..','..','..','coap')
p = os.path.abspath(p)
sys.path.insert(0,p)

from coap import coap
from coap import coapDefines as d
import random

class CoapConsole(cmd.Cmd):
    def __init__(self):
        cmd.Cmd.__init__(self)
        self.intro = """
UFUSP Wireles Network.
Ensure that openvisualizer is running.
"""
        self.prompt = '> '
        self.coap = coap.coap(udpPort=self.get_random_port())

    def get_random_port(self):
        return random.randint(49152,65535)

    def split_args(self,arg):
        args = arg.split(' ')
        return args
    
    def coap_get(self,uri):
        try:
            d = self.coap.GET(uri)
            d = ''.join([ chr(c) for c in d ])
            r = json.loads(d)
        except Exception, e:
            print 'Error {0}'.format(repr(e))
        else:
            return r

    def coap_put(self,uri,payload=''):
        if payload:
            payload = [ ord(c) for c in payload ]
        try:
            self.coap.PUT(uri,payload=payload)
        except Exception, e:
            print 'Error {0}'.format(repr(e))

    def do_get(self, args):
        uri = self.split_args(args)
        if len(uri) != 1:
            print self.help_get()
            return
        r = self.coap_get(uri[0])
        print r
        
    def do_put(self, args):
        uri = self.split_args(args)
        if len(uri) < 1:
            print self.help_put()
            return
        if len(uri) > 1:
            payload = ' '.join(uri[1:])
        else:
            payload = ''
        self.coap_put(uri[0],payload)

    def print_dict(self,d,level=0):
        s = []
        spc = '    '*level
        keys = d.keys()
        keys.sort()
        mk = max([ len(k) for k in keys ])
        frm = '%%s%%-0%ds: %%s' % (mk)
        for k in keys:
            v = d[k]
            f = frm % (spc,str(k),str(v))
            s.append(f)
        return '\n'.join(s)
    
    def do_profile(self,args):
        uri = self.split_args(args)
        if len(uri) != 1:
            print self.help_profile()
            return
        ip = uri[0]
        uri = 'coap://[{0}]/d'.format(ip)
        data = self.coap_get(uri)
        print 'Board description:\n{0}'.format(self.print_dict(data,1))
        if data.has_key('npts'):
            for index in range(data['npts']):
                uri = 'coap://[{0}]/d/pt/{1}'.format(ip,index)
                v = self.coap_get(uri)
                print 'Point [{0}] description:\n{1}'.format(index,self.print_dict(v,1))
        else:
            print 'No points'
    def do_quit(self, arg):
        if self.coap:
            self.coap.close()        
        sys.exit(1)

    def help_put(self):
        print """COAP GET Request
Sintaxe: put uri payload
Example: put coap://[bbbb::12:4b00:2f4:afc0]/s/1/1
         put coap://[bbbb::12:4b00:2f4:afc0]/s/1/1 data to be sent
"""
        
    def help_get(self):
        print """COAP PUT Request
Sintaxe: get uri
Example: get coap://[bbbb::12:4b00:2f4:afc0]/s/1
"""

    def help_profile(self):
        print """Get the mote profile
Example: profile bbbb::12:4b00:2f4:afc0
"""
        
    def help_quit(self):
        print "Exit"

    def default(self,line):
        print self.do_help('')

cli = CoapConsole()
cli.cmdloop()
