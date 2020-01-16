"""
Whois client for python

transliteration of:
http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

Copyright (c) 2020 Chris Wolf

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

  Last edited by:  $Author$
              on:  $DateTime$
        Revision:  $Revision$
              Id:  $Id$
          Author:  Chris Wolf
"""
from ipwhois import IPWhois
from tkinter import *
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import urllib.request
import sys
import socket
import optparse
import locale
import urllib.request
import json

# import pdb
filename = ''


class NICClient(object):
    ABUSEHOST = "whois.abuse.net"
    NICHOST = "whois.crsnic.net"
    INICHOST = "whois.networksolutions.com"
    DNICHOST = "whois.nic.mil"
    GNICHOST = "whois.nic.gov"
    ANICHOST = "whois.kisa.or.kr"  # whois.arin.net
    LNICHOST = "whois.lacnic.net"
    RNICHOST = "whois.ripe.net"
    PNICHOST = "whois.apnic.net"
    MNICHOST = "whois.ra.net"
    QNICHOST_TAIL = ".whois-servers.net"
    SNICHOST = "whois.6bone.net"
    BNICHOST = "whois.registro.br"  # whois.registro.br
    NORIDHOST = "whois.norid.no"
    IANAHOST = "whois.iana.org"
    GERMNICHOST = "de.whois-servers.net"
    DEFAULT_PORT = "nicname"
    WHOIS_SERVER_ID = "Whois Server:"
    WHOIS_ORG_SERVER_ID = "Registrant Street1:Whois Server:"

    WHOIS_RECURSE = 0x01
    WHOIS_QUICK = 0x02

    ip_whois = [LNICHOST, RNICHOST, PNICHOST, BNICHOST]

    language, encoding = locale.getdefaultlocale()

    def __init__(self):
        self.use_qnichost = False

    def findwhois_server(self, buf, hostname):
        """Search the initial TLD lookup results for the regional-specifc
        whois server for getting contact details.
        """
        nhost = None
        parts_index = 1
        start = buf.find(NICClient.WHOIS_SERVER_ID)
        if (start == -1):
            start = buf.find(NICClient.WHOIS_ORG_SERVER_ID)
            parts_index = 2

        if (start > -1):
            end = buf[start:].find('\n')
            whois_line = buf[start:end + start]
            whois_parts = whois_line.split(':')
            nhost = whois_parts[parts_index].strip()
        elif (hostname == NICClient.ANICHOST):
            for nichost in NICClient.ip_whois:
                if (buf.find(nichost) != -1):
                    nhost = nichost
                    break
        return nhost

    def whois(self, query, hostname, flags):
        """Perform initial lookup with TLD whois server
        then, if the quick flag is false, search that result
        for the region-specifc whois server and do a lookup
        there for contact details
        """
        # pdb.set_trace()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, 43))
        if (hostname == NICClient.GERMNICHOST):
            s.send(("-T dn,ace -C US-ASCII " + query + "\r\n").encode())
        else:
            s.send((query + "\r\n").encode())
        response = b""
        while True:
            d = s.recv(4096)
            response += d
            if not d:
                break
        s.close()
        # pdb.set_trace()
        nhost = None
        if (flags & NICClient.WHOIS_RECURSE and nhost == None):
            nhost = self.findwhois_server(response.decode('utf-8', 'replace'), hostname)
        if (nhost != None):
            response += self.whois(query, nhost, 0)
        return response

    def choose_server(self, domain):
        """Choose initial lookup NIC host"""
        if (domain.endswith("-NORID")):
            return NICClient.NORIDHOST
        pos = domain.rfind('.')
        if (pos == -1):
            return None
        tld = domain[pos + 1:]
        if (tld[0].isdigit()):
            return NICClient.ANICHOST

        return tld + NICClient.QNICHOST_TAIL

    def whois_lookup(self, options, query_arg, flags):
        """Main entry point: Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server, then if quick
        flag is false, perform a second lookup on the region-specific
        server for contact records"""
        nichost = None
        # pdb.set_trace()
        # this would be the case when this function is called by other then main
        if (options == None):
            options = {}

        if (('whoishost' not in options or options['whoishost'] == None)
                and ('country' not in options or options['country'] == None)):
            self.use_qnichost = True
            options['whoishost'] = NICClient.NICHOST
            if (not (flags & NICClient.WHOIS_QUICK)):
                flags |= NICClient.WHOIS_RECURSE

        if ('country' in options and options['country'] != None):
            result = self.whois(query_arg, options['country'] + NICClient.QNICHOST_TAIL, flags)
        elif (self.use_qnichost):
            nichost = self.choose_server(query_arg)
            if (nichost != None):
                result = self.whois(query_arg, nichost, flags)
        else:
            result = self.whois(query_arg, options['whoishost'], flags)

        return result.decode('utf-8', 'replace')


# ---- END OF NICClient class def ---------------------

def parse_command_line(argv):
    """Options handling mostly follows the UNIX whois(1) man page, except
    long-form options can also be used.
    """
    flags = 0

    usage = "usage: %prog [options] name"

    parser = optparse.OptionParser(add_help_option=False, usage=usage)
    parser.add_option("-a", "--arin", action="store_const",
                      const=NICClient.ANICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ANICHOST)
    parser.add_option("-A", "--apnic", action="store_const",
                      const=NICClient.PNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.PNICHOST)
    parser.add_option("-b", "--abuse", action="store_const",
                      const=NICClient.ABUSEHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.ABUSEHOST)
    parser.add_option("-c", "--country", action="store",
                      type="string", dest="country",
                      help="Lookup using country-specific NIC")
    parser.add_option("-d", "--mil", action="store_const",
                      const=NICClient.DNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.DNICHOST)
    parser.add_option("-g", "--gov", action="store_const",
                      const=NICClient.GNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.GNICHOST)
    parser.add_option("-h", "--host", action="store",
                      type="string", dest="whoishost",
                      help="Lookup using specified whois host")
    parser.add_option("-i", "--nws", action="store_const",
                      const=NICClient.INICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.INICHOST)
    parser.add_option("-I", "--iana", action="store_const",
                      const=NICClient.IANAHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.IANAHOST)
    parser.add_option("-l", "--lcanic", action="store_const",
                      const=NICClient.LNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.LNICHOST)
    parser.add_option("-m", "--ra", action="store_const",
                      const=NICClient.MNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.MNICHOST)
    parser.add_option("-p", "--port", action="store",
                      type="int", dest="port",
                      help="Lookup using specified tcp port")
    parser.add_option("-Q", "--quick", action="store_true",
                      dest="b_quicklookup",
                      help="Perform quick lookup")
    parser.add_option("-r", "--ripe", action="store_const",
                      const=NICClient.RNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.RNICHOST)
    parser.add_option("-R", "--ru", action="store_const",
                      const="ru", dest="country",
                      help="Lookup Russian NIC")
    parser.add_option("-6", "--6bone", action="store_const",
                      const=NICClient.SNICHOST, dest="whoishost",
                      help="Lookup using host " + NICClient.SNICHOST)
    parser.add_option("-?", "--help", action="help")

    return parser.parse_args(argv)


list_ = ['None', ' ', 'NA']

def read_dict(data):
    str_ = json.loads(data)
    return str_

def read_dict_py3whois(data):
    list_ = {data}
    list_ = list(list_)
    for i in range(len(list_)):
        dict_ = {}
        for s in list_[i].split('\n'):
            x = s.strip()
            if x == "" or x[0] == '#':
                continue
            if x.find(':') == -1:
                continue
            key = x[:x.find(':')]
            key = key.strip()
            if x.find(':') == len(x) - 1:
                continue
            value = x[x.find(':') + 1:]
            value = value.strip()
            dict_[key] = value
            list_[i] = dict_
        return dict_

def read_ipinfoAS(data):
    result = "https://ipinfo.io/" + str(data)
    result = urllib.request.urlopen(result).read().decode("utf-8")
    result = read_dict_py3whois(result)

    orgname = str(result.get('org-name'))
    OrgName = str(result.get('OrgName'))
    asname = str(result.get('as-name'))
    ASName = str(result.get('ASName'))
    ASNumber = str(result.get('ASNumber'))

    result = str(result)
    serach = '-'

    if result not in list_:
        if serach in orgname:
            result = ASNumber+"\t"+OrgName
        elif serach in OrgName:
            result = ASNumber+"\t"+asname
        elif serach in asname:
            result = ASNumber+"\t"+ASName
        else:
            result = ASNumber+"\t"+orgname
        return result
    else:
        result = "Unknow"
        return result

def read_bgpview(asn):
    result = "https://api.bgpview.io/asn/" + str(asn)
    result = urllib.request.urlopen(result).read().decode("utf-8")
    result = read_dict(result)

    result_asn = str(result['data']['asn'])
    result_des = str(result['data']['description_short'])
    result_name = str(result['data']['name'])
    result_website = str(result['data']['website'])

    result = str(result)
    serach = '-'

    #result = "AS"+result_asn + "\t" + result_des + "\t" + result_name + "\t" + result_website
    if result not in list_:
        if serach in result_name:
            result = "AS"+result_asn + "\t" + result_des + "\t"+ result_website
            return result
        else:
            result = "AS" + result_asn + "\t" + result_name + "\t" + result_website
            return result
    else:
        try:
            result = read_ipinfoAS(asn)
            return result
        except:
            result = None
            return result

def read_py3whois(data):
    nic_client = NICClient()
    result = nic_client.whois_lookup({}, data, 0)
    result = read_dict_py3whois(result)

    asn = str(result['origin'])

    if asn not in list_:
        return asn
    else:
        asn = None
        return asn

def read_ipapi(data):
    result = "https://ipapi.co/" + data +"/json"
    result = urllib.request.urlopen(result).read().decode("utf-8")
    result = read_dict(result)

    asn = str(result['asn'])

    if asn not in list_:
        return asn
    else:
        raise Exception

def read_asnsearch(data):
    ip = data.rstrip()
    result = "https://api.bgpview.io/ip/" + ip
    result = urllib.request.urlopen(result).read().decode("utf-8")
    result = read_dict(result)

    asn = result['data']['prefixes'][0]['asn']['asn']

    if asn not in list_:
        return asn
    else:
        try:
            result = read_ipapi(ip)
            return result
        except:
            result = read_py3whois(ip)
            return result

def savefile():
    save_text_as = filedialog.asksaveasfile(mode='w', defaultextension='.txt')

    if save_text_as:
        text_to_save = textArea.get('1.0', 'end-1c')
        save_text_as.write(text_to_save)
        save_text_as.close()
    else:
        messagebox.showinfo("Error", "Cancelled")


def ipfile():
    global filename
    filename = filedialog.askopenfilename(initialdir="/", title="Open File",filetypes=(("Text Files", "*.txt"), ("ALL Files", "*.*")))
    textArea.delete('1.0', tk.END)
    try:
        if filename:
            lines = open(filename)
            for line in lines.readlines():
                if not line:
                    break
                data = line.rstrip()
                try:
                    result_asn = read_asnsearch(data)
                except:
                    result_asn = None
                Result_asn = result_asn
                try:
                    print("Serach: "+data)
                    result = read_bgpview(Result_asn)
                except:
                    print("Fail function")
                    result = None
                Filter = data + "\t" + str(result)
                textArea.insert(tk.END, Filter + "\n")
            # textArea.insert(tk.END, the_file.read())
            lines.close()
        elif filename == '':
            messagebox.showinfo("Cancel", "You clicked Cancel")
            print("Cancel")
    except IOError:
        messagebox.showinfo("Error", "Could not open file")


form = tk.Tk()
form.geometry('960x540')
form.title("IPWhois")

# menubar
menubar = tk.Menu(form)
filemenubar = tk.Menu(menubar, tearoff=0)
filemenubar.add_command(label="SaveFiles", command=savefile)
menubar.add_cascade(label="File", menu=filemenubar)
form.config(menu=menubar)

# text
textArea = tk.Text(form, height=30, width=150, wrap=tk.WORD)
textArea.pack()

# button
btn1 = Button(form, text='IP_OPENFILE', command=ipfile)
# btn2 = Button(form, text='ASN',command=asn)
btn1.pack(side=RIGHT)
# btn2.pack(side=RIGHT)

# layout
form.mainloop()
