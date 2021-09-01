import socket
import smtplib
import urllib
import requests
from requests import *
import sys
import os
import pikepdf
from tqdm import tqdm
def clear():
	os.system("clear")
clear()
print('''\033[93m
dP         .d888888  d8888888P dP    dP d888888P  .88888.   .88888.  dP        .d88888b  
88        d8'    88       .d8' Y8.  .8P    88    d8'   `8b d8'   `8b 88        88.    "' 
88        88aaaaa88a    .d8'    Y8aa8P     88    88     88 88     88 88        `Y88888b. 
88        88     88   .d8'        88       88    88     88 88     88 88              `8b 
88        88     88  d8'          88       88    Y8.   .8P Y8.   .8P 88        d8'   .8P 
88888888P 88     88  Y8888888P    dP       dP     `8888P'   `8888P'  88888888P  Y88888P  
ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
      		    
      		    /+/Coded with \u2764\ufe0f by YA2SIR /+/ 
      		    
                                                                     \033[93m''')                       
MENU='''
	1-Host2ip
	2-Subdomain finder
	3-Directory brute force
	4-Port scanner
	5-File cracker (zip,pdf...)
	6-View your public ip
'''
print(MENU)
ch=int(input("====> "))

def host2ip():
	clear()
	print("+++HOST2IP+++ (host to ip adress)")
	host=input("Enter the hostname here ==>  ")
	ip=socket.gethostbyname(host)
	print("The ip of ",host,"is ==> ",ip)
	
def subfinder():
    clear()
    print("            +++SUBDOMAINS FINDER+++")
    domain=input("Enter the domain name : ")
    filetxt=input("Enter the wordlist : ")
    txt=open(filetxt)
    content = txt.read()
    subdomains = content.splitlines()
    discovered_subdomains = []
    for subdomain in subdomains:
        url = f"http://{subdomain}.{domain}"
        try:
            requests.get(url)
        except requests.ConnectionError:
    	    pass
        else:
            print("[+] Discovered subdomain:", url)

def Dirbf():
    clear()
    print("            +++Dir brute-force+++")
    domain=input("Enter the target : ")
    filetxt=input("Enter the wordlist : ")
    txt=open(filetxt)
    content = txt.read()
    dirs = content.splitlines()
    for directory in dirs:
        url = f"http://{domain}/{directory}"
        response = requests.get(url)
    if (response.status_code == 200):
    	print ("[+] found : ",url)
    else:	
    	pass
def portScanner():
	clear()
	portSlogo=("+++PORT SCANNER+++")
	print(portSlogo)
	t=input("Enter the hostnamee of your target ==> ")
	target = socket.gethostbyname(t)

	print("Scanning Target: " + t)
	print("Scanning started...")

	try:

		for port in range(1,80):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(1)
		
			result = s.connect_ex((target,port))
		if result ==0:
			print("Port {} is open".format(port))
		s.close()
			
	except KeyboardInterrupt:
		print("Operation cancelled by user !")
		sys.exit()
	except socket.gaierror:
		print("Hostname Could Not Be Resolved !")
		sys.exit()
	except socket.error:
		print("Server not responding !")
		sys.exit()
def pubip():
	clear()
	publicip = get('https://api.ipify.org').text
	print("Your public IP address is==>", publicip)	
def zipcracker():
	print("+++CRACK ZIP FILE+++")
	zipfilename =input("Enter the zip file path : ")
	dictionary =input("Enter the wordlist path : ")

	password = None
	zip_file = zipfile.ZipFile(zipfilename)
	with open(dictionary, 'r') as f:
		for line in f.readlines():
			password = line.strip('\n')
			try:
				zip_file.extractall(pwd=password)
				password =("Password found: ",password)
			except:
				pass
	print(password)
def pdfcracker():
	passwords = []

# Contain passwords in text file
	pdffile=input("Enter the pdf file : ")
	password_text_file =input("Enter the wordlist : ")
	for line in open(password_text_file):
		passwords.append(line.strip())
	
# iterate over passwords
	for password in tqdm(passwords, pdffile):
		try:
		
		# open PDF file and check each password
			with pikepdf.open(pdffile,
						password = password) as p:
			
			# If password is correct, break the loop
							print("[+] Password found:", password)
			break
			
	# If password will not match, it will raise PasswordError
		except pikepdf._qpdf.PasswordError as e:
		    pass

def filecracker():
	print('''
	1-Crack zip file 
	2-Crack pdf file''')
	crch=int(input("====> "))
	if crch==1:
		zipcracker()
	elif crch==2:
		pdfcracker()
		
if ch==1:
	host2ip()
elif ch==2:
	subfinder()
elif ch==3:
	Dirbf()
elif ch==4:
	portScanner()
elif ch==5:
	filecracker()
elif ch==6:
	pubip()