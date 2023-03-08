import requests
import whois
import pandas as pd
import argparse
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument('--list')
parser.add_argument('--filename',default='WebScan') #output file name
parser.add_argument('--timeout',type=int,default=60)
parser.add_argument('--whois', action='store_true')
parser.add_argument('--export', action='store_true')
args = parser.parse_args()
addresslist = args.list
filename = args.filename + '.csv'
table = []
headers = ['address','response']
if args.whois == True: headers.extend(['domain','registrar','name server'])

def httprequest(addr):
	http = {}
	try:
		url = "https://" + addr
		request = requests.get(url,timeout=args.timeout,verify=False,allow_redirects=True)
	except:
		http['response'] = "No Response"
	else:
		http['response'] = request.status_code
	return http
	
def whoisquery(addr):
	who = {}
	try:
		owl = whois.query(addr)
	except:
		who['domain'] = ""
		who['registrar'] = ""
		who['name server'] = ""
	else:
		who['domain'] = owl.name
		who['registrar'] = owl.registrar
		who['name server'] = owl.name_servers
	return who
		
def buildtable(table):	
	df = pd.DataFrame(table)
	df.to_csv(filename, index=False, header=headers)

with open(addresslist) as addrlist:
	for addr in addrlist:
		addr = addr.strip()
		row = {}
		row['address'] = addr
		row.update(httprequest(addr))
		
		if args.whois == True:
			row.update(whoisquery(addr))
		if args.export == True:
			table.append(list(row.values()))		
		print (row)

if args.export == True:
	buildtable(table)
