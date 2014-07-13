import os
import sys
from Tkinter import *
import tkMessageBox
import re
from Queue import Queue
import threading
import struct

p = os.path.dirname(sys.argv[0])
p = os.path.join(p,'..','..','..','..','coap')
p = os.path.abspath(p)
sys.path.insert(0,p)

from coap import coap

class SendCoap(threading.Thread):
    def __init__(self,addr,method,period,win,queue):
        threading.Thread.__init__(self)
        self.addr = addr
        self.method = method
        self.period = period
        self.win = win
        self.queue = queue
        self.running = False
        self.coap = coap.coap()
        self.timer_cbk = None
        self.tmr = 0

    def wait_answer(self):
        self.tmr = self.tmr + 1
        if self.running:
            self.timer_cbk = self.win.after(1000,self.wait_answer)
            self.update_status("STATUS","Waiting answer ({0}) ...".format(self.tmr))

    def exec_request(self):
        if self.method == 'GET':
            uri = 'coap://[{0}]/strm/period'.format(self.addr)
            r = self.coap.GET(uri)
            self.per = struct.unpack('>H',''.join([ chr(c) for c in r ]))[0]
            self.update_status("PERIOD",self.per)
        else:
            uri = 'coap://[{0}]/strm/period'.format(self.addr)
            per = [ ord(c) for c in struct.pack('>H',self.period) ]
            r = self.coap.PUT(uri,payload=per)

    def run(self):
        self.running = True
        while self.running:
            self.tmr = 0
            self.update_status("STATUS","Sending coap")
            self.timer_cbk = self.win.after(1000,self.wait_answer)
            try:
                self.exec_request()
            except Exception, e:
                self.update_status("STATUS","Failed {0}".format(repr(e)))
            else:
                self.update_status("STATUS","Success !")
            self.win.after_cancel(self.timer_cbk)
            self.running = False

    def quit(self):
        self.coap.close()
        if self.timer_cbk:
            self.win.after_cancel(self.timer_cbk)
        self.running = False

    def is_running(self):
        return self.running

    def update_status(self,t,m):
        self.queue.put((t,m))
        try:
            self.win.event_generate('<<UpdateStatus>>', when='tail')
        except:
            pass

class UDPStormGUI(object):
    def __init__(self, master):
        self.master = master
        self.ipv6_addr = StringVar()
        self.ipv6_addr.set('bbbb::')
        self.period = IntVar()
        self.period.set(0)
        self.status = StringVar()
        self.status.set('')

        self.create_gui()

        self.task = None
        self.queue = Queue()
        self.master.bind('<<UpdateStatus>>', self.update_status)

        self.master.mainloop()

    def update_status(self,event):
        t,m = self.queue.get()
        if t == "PERIOD":
            self.period.set(m)
        elif t == "STATUS":
            self.status.set(m)
        else:
            self.status.set(repr(m))
        self.master.update_idletasks()

    def create_gui(self):
        self.master.wm_title("UDP Storm")

        f = Frame(self.master,padx=5,pady=5)
        Label(f,text="IETF90 plugfest - UDP Storm for OpenWSN").pack(side=LEFT,expand=NO)
        f.pack(side=TOP,expand=YES,fill=X)

        f = Frame(self.master,height=2,bd=1,relief=SUNKEN,padx=5,pady=5)
        f.pack(side=TOP,fill=X)

        f = Frame(self.master,padx=5,pady=5)
        Label(f,text="coap://[").pack(side=LEFT,expand=NO)
        Entry(f,textvariable=self.ipv6_addr,width=40).pack(side=LEFT,expand=YES,fill=X)
        Label(f,text="]/strm/period=").pack(side=LEFT,expand=NO)
        Entry(f,textvariable=self.period,width=10).pack(side=LEFT,expand=NO)
        f.pack(side=TOP,expand=YES,fill=X)

        f = Frame(self.master,height=2,bd=1,relief=SUNKEN,padx=5,pady=5)
        f.pack(side=TOP,fill=X)

        f = Frame(self.master,padx=5,pady=5)
        Button(f,text="GET",width=10,command=self.get_cmd,default=ACTIVE).pack(side=RIGHT,expand=NO)
        Button(f,text="PUT",width=10,command=self.put_cmd,default=ACTIVE).pack(side=RIGHT,expand=NO)
        Label(f,textvariable=self.status,anchor=W).pack(side=LEFT,expand=YES,fill=X)
        f.pack(side=TOP,expand=YES,fill=X)

        self.master.protocol("WM_DELETE_WINDOW", self.close)

    def validate(self,check_per=True):
        if check_per:
            try:
                per = self.period.get()
            except:
                tkMessageBox.showwarning("Period","Invalid number for period")
                return False

            if (per < 0) or (per > (2**16-1)):
                tkMessageBox.showwarning("Period","Invalid range for period [0-65535]")
                return False

        ipv6 = self.ipv6_addr.get().strip()
        self.ipv6_addr.set(ipv6)

        # http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        pattern = r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|" + \
            r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|" + \
            r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|" + \
            r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|" + \
            r":((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|" + \
            r"::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|" + \
            r"(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|" + \
            r"1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b"

        if re.match(pattern, ipv6):
            return True
        else:
            tkMessageBox.showwarning("IPv6","Invalid IPv6 address")
            return False

        return True

    def kill_task(self):
        if self.task:
            if self.task.is_running():
                self.status.set('Cancelling')
                self.master.update_idletasks()
            self.task.quit()

    def get_cmd(self, event=None):
        if self.validate(False):
            self.kill_task()
            self.status.set('')
            self.master.update_idletasks()
            ipv6 = self.ipv6_addr.get().strip()
            per = self.period.get()
            self.task = SendCoap(ipv6,'GET',per,self.master,self.queue)
            self.task.start()

    def put_cmd(self, event=None):
        if self.validate():
            self.kill_task()
            self.status.set('')
            self.master.update_idletasks()
            ipv6 = self.ipv6_addr.get().strip()
            per = self.period.get()
            self.task = SendCoap(ipv6,'PUT',per,self.master,self.queue)
            self.task.start()

    def close(self):
        self.kill_task()
        self.master.destroy()

UDPStormGUI(Tk())


