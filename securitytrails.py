import requests
import sys
import argparse
import json
import os
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from urllib.error import HTTPError

urllib3.disable_warnings(InsecureRequestWarning) # 警告の抑制


parser = argparse.ArgumentParser()
parser.add_argument('--details', help='input domain if you want to know details.')
parser.add_argument('--subdomains', help='input domain if you want to obtain related subdomains.')
parser.add_argument('--check', help='Check your API limits.',default=None, action='store_true')
parser.add_argument('--domainlist', action='store',
                    type=argparse.FileType('r'), nargs='?', 
                    help='input domain list as text file.')
args = parser.parse_args()

accept = "application/json"

APIKEY = os.getenv('APIKEY') #環境変数設定 e.g)windows:$env:APIKEY="yourapikey", bash: export APIKEY="yourapikey"  
if not APIKEY:
    print('[*] Please set your APIKEY in os environment.')
    exit()

def domainlists():
    domains = args.domainlist.readlines()
    for domain in domains:
        try:
            domain = domain.replace("\n", "")
            url = "https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=true&include_inactive=true".format(domain)

            headers = {
                "accept": accept,
                "APIKEY": APIKEY
            }
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            #print(response.json())
            count = response.json()["subdomain_count"]
            print("[*] Obtained "+str(count)+" subdomains as {}.".format(domain))
            subdomains = response.json()["subdomains"]
            for s in subdomains:
                print(s+'.'+domain)
            #outputfile = 'output_{}.txt'.format(domain)
        except HTTPError as e:
            raise e

def detailsdomain():
    try:
        url = "https://api.securitytrails.com/v1/domain/{args.details}".format(args=args)

        headers = {
            "accept": accept,
            "APIKEY": APIKEY
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        print(response.text)
    except HTTPError as e:
        raise e
    
        
def getsubdomains():
    try:
        url = "https://api.securitytrails.com/v1/domain/{args.subdomains}/subdomains?children_only=true&include_inactive=true".format(args=args)

        headers = {
            "accept": accept,
            "APIKEY": APIKEY
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        #print(response.json())
        count = response.json()["subdomain_count"]
        print("[*] Obtained "+str(count)+" subdomains.")
        subdomains = response.json()["subdomains"]
        for s in subdomains:
            print(s+'.{args.subdomains}'.format(args=args))
    except HTTPError as e:
        raise e


def statuscheck():
    try:
        url = "https://api.securitytrails.com/v1/account/usage"
        headers = {
            "accept": accept,
            "APIKEY": APIKEY
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        allow = response.json()["allowed_monthly_usage"]
        print("[*] Allowed monthly usage: "+str(allow))
        current = response.json()["current_monthly_usage"]
        print("[*] Current monthly usage: "+str(current))
    except HTTPError as e:
        raise e


def main():
    if args.domainlist:
        domainlists()
    elif args.details:
        detailsdomain()
    elif args.subdomains:
        getsubdomains()
    elif args.check:
        statuscheck()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()