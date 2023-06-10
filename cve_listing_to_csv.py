import sys
import requests
import time
import json
import csv
import os

if len(sys.argv) == 1:
    print('Usage: {} <CVE LIST>'.format(sys.argv[0]))
    sys.exit(1)

cvelist = sys.argv[1]
url_nvd = 'https://services.nvd.nist.gov/rest/json/cve/1.0/'
url_mitre = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name='
apikey = os.getenv('apikey')
payload = {'apiKey':apikey}

def get_cve_info(cve):
    cve_info = {}

    # Get CVE summary from NVD
    r = requests.get(url_nvd + cve, params=payload)
    time.sleep(1)
    json_data = json.loads(r.text)
    result = json_data['result']['CVE_Items']
    vuln = result[0]

    # Get CVSS score (v3 or v2)
    if 'baseMetricV3' in vuln['impact']:
        vectorstring = vuln['impact']['baseMetricV3']['cvssV3']['vectorString']
        attackvector = vuln['impact']['baseMetricV3']['cvssV3']['attackVector']
        cvss_base_score = vuln['impact']['baseMetricV3']['cvssV3']['baseScore']
        cvss_base_severity = vuln['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    elif 'baseMetricV2' in vuln['impact']:
        vectorstring = vuln['impact']['baseMetricV2']['cvssV2']['vectorString']
        attackvector = vuln['impact']['baseMetricV2']['cvssV2']['accessVector']
        cvss_base_score = vuln['impact']['baseMetricV2']['cvssV2']['baseScore']
        cvss_base_severity = vuln['impact']['baseMetricV2']['severity']

    # Get CVE title and MITRE URL
    cve_info['title'] = vuln['cve']['description']['description_data'][0]['value']
    cve_info['mitre_url'] = url_mitre + cve

    # Add CVSS score to the dictionary
    cve_info['vectorstring'] = vectorstring
    cve_info['attackvector'] = attackvector
    cve_info['cvss_base_score'] = cvss_base_score
    cve_info['cvss_base_severity'] = cvss_base_severity

    return cve_info

# CSV summary is output to output.csv on current directory.
def cve_summarize():
    with open('output.csv', mode='w') as file:
        writer = csv.writer(file)
        writer.writerow(['CVE ID', 'Title', 'MITRE URL', 'Vector String', 'Attack Vector', 'CVSS Base Score', 'CVSS Base Severity'])

        with open(cvelist, 'r') as f:
            for cve in f:
                cve = cve.rstrip('\n')
                cve_info = get_cve_info(cve)
                writer.writerow([cve, cve_info['title'], cve_info['mitre_url'], cve_info['vectorstring'], cve_info['attackvector'], cve_info['cvss_base_score'], cve_info['cvss_base_severity']])
                


def main():
    cve_summarize()

if __name__ == '__main__':
    main()
