import requests
import whois
import pandas as pd
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--list')
parser.add_argument('--filename',default='WebScan')
parser.add_argument('--timeout',type=int,default=60)
args = parser.parse_args()

addresslist = args.list
filename = args.filename + '.csv'
table = []
headers = ['address','response','domain','registrar','name server']

with open(addresslist) as list:
	row = {}
	for addr in list:
		addr = addr.strip()
		row['address'] = addr
		print (addr)
		
		#http request		
		try:
			url = "http://" + addr
			request = requests.get(url,timeout=args.timeout,verify=False,allow_redirects=False )
		except:
			row['response'] = "No Response"
		else:
			row['response'] = request.status_code
			
		#Whois
		try:
			owl = whois.query(addr)
		except:
			row['domain'] = ""
			row['registrar'] = ""
			row['name server'] = ""
		else:
			row['domain'] = owl.name
			row['registrar'] = owl.registrar
			row['name server'] = owl.name_servers
		
		table.append([row['address'],row['response'],row['domain'],row['registrar'],row['name server']])
		
df = pd.DataFrame(table)
df.to_csv(filename, index=False, header=headers)
