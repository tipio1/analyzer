# coding: utf-8
"""_summary_
V1, July 23, tipio, SOC Analyst Intern and Shyan / based on the example of Sooty
Principal scan functions
"""


import json
import os
import requests
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from bs4 import BeautifulSoup as bs
import urllib.request
from utils import *


# Analysis functions:
class Functions:
    @staticmethod
    def whois():
        """_summary_
        Check Whois and return the results in a dedicated file in the reports directory.
        """
        print(Color.GREEN + "[+] whois report: " + Color.END)
        (
            os.system("whois " + IP + " | grep -E 'Registrar WHOIS Server|Name Server|Creation Date|Registrar URL|Registrar Registration Expiration Date|Registrant Organization|Registrant Country|Name Server' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u")
            or
            os.system("whois " + IP + " | grep -E 'netname|country|person|route' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u")
            or
            os.system("whois " + IP + " | grep -E 'NetName|Organization|Country|RegDate' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u")
        )
        """ Bug with opening and writing to file (Agust 23)
        with open('reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            (
                os.system("whois " + IP + " | grep -E 'Registrar WHOIS Server|Name Server|Creation Date|Registrar URL|Registrar Registration Expiration Date|Registrant Organization|Registrant Country|Name Server' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u > " + "reports/" + TODAY + "/" + str(DOMAIN_NAME_TO_IP) + ".txt")
                or 
                os.system("whois " + IP + " | grep -E 'netname|country|person|route' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u > " + "reports/" + TODAY + "/" + str(DOMAIN_NAME_TO_IP) + ".txt")
                or
                os.system("whois " + IP + " | grep -E 'NetName|Organization|Country|RegDate' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u > " + "reports/" + TODAY + "/" + str(DOMAIN_NAME_TO_IP) + ".txt")
            )
        """


    @staticmethod
    def virusTotal():
        """_summary_
        Check VT and return the results in a dedicated file in the reports directory.
        """
        try:
            print(Color.GREEN + "[+] VirusTotal report:" + Color.END)
            global VT_COUNT
            with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
                fileReport.write("\n --------------------------------- ")
                fileReport.write("\n VirusTotal report:")
                fileReport.write("\n --------------------------------- \n")
                with open(KEY_FILE, "r") as file:
                    configFile = json.load(file)
                    url = 'https://www.virustotal.com/vtapi/v2/url/report'
                    params = {'apikey': configFile['api']['virus total'], 'resource': DOMAIN_NAME_TO_IP}
                    response = requests.get(url, params=params)
                    if response.status_code == 200:
                        count = 0
                        result = response.json()
                        fileReport.write(result['permalink'])
                        fileReport.write("\n ---------------------------------")
                        print("[+] The VirusTotal report link is stored in the previously created file")
                        if result['positives'] == 0:
                            print("[!] No positives results found in " + str(result['total']) + " AV scanned")
                            fileReport.write(result['permalink'])
                            fileReport.write('[!] Clean on Virus Total')
                            fileReport.close()
                            VT_COUNT = [count, result['total']]
                        if result['positives'] != 0:
                            print('[+] Positives results found: ' )
                            for key in result['scans']:
                                if result['scans'][key]['detected'] == True:  # check for other detections, like "suspicious site"
                                    count += 1
                                    charToRemove = ["{detected: ", "}"]
                                    stringToDisplay = str(result['scans'][key]).replace("'", '')
                                    for char in charToRemove:
                                        stringToDisplay = stringToDisplay.replace(char, "")
                                    print("\t- ", key, ":", stringToDisplay)
                                    fileReport.write("\n")
                                    fileReport.write(key)
                                    fileReport.write(" : ")
                                    fileReport.write(str(result['scans'][key]))
                                else:
                                    count == count
                            print(Color.GREEN + "[+] Number of detections: ", str(count) + Color.END)
                            fileReport.write("\n --------------------------------- \n")
                            fileReport.write('Number of detections: ')
                            fileReport.write(str(count))
                            fileReport.close()
                            VT_COUNT = [count, result['total']]
        except Exception:
            print(Color.RED + "[!] Error in the Virus Total conf, check it" + Color.END)

  
    @staticmethod
    def scrapDuggyTuxyRepo():
        """
        These are the IP addresses of the most active Botnets/Zombies/Scanners in European Cyber Space
        """
        try:
            print(Color.GREEN + "[+] Duggy Tuxy report:" + Color.END)
            count = 0
            url = "https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/main/botnets_zombies_scanner_spam_ips.txt"
            page = urllib.request.urlopen(url,timeout=5).read()
            soup = bs(page, 'html.parser')  # or 'lxml'
            text = soup.get_text()
            if DOMAIN_NAME_TO_IP in str(text):
                count += 1
                print('[!]', DOMAIN_NAME_TO_IP, 'Found in the list. Possible active Botnets/Zombies/Scanners in European Cyber Space')
            else:
                count == count
                print('[+]', DOMAIN_NAME_TO_IP, "Not found in the Duggy Tuxy's list")
            global DUGGY_COUNT
            DUGGY_COUNT = count
        except Exception:
            print(Color.RED + "[!] Error with Duggy Tuxy's list, check repo" + Color.END)
        
        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n --------------------------------- ")
            fileReport.write("\n Duggy Tuxy report:")
            fileReport.write("\n --------------------------------- \n")
            if count != 0:
                fileReport.write('[!] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(' Found in the list. Possible active Botnets/Zombies/Scanners in European Cyber Space')
            if count == 0:
                fileReport.write('[+] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(" Not found in the Duggy Tuxy's list")
                fileReport.close()


    @staticmethod
    def criminalIP():
        try:
            print(Color.GREEN + "[+] Criminal IP report:" + Color.END)
            url = (f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={DOMAIN_NAME_TO_IP}")
            payload = {}
            with open(KEY_FILE, "r") as file:
                configFile = json.load(file)
                headers = {'x-api-key': configFile['api']['criminal ip']}
                response = requests.request("GET", url, headers=headers, data=payload)
                result = response.json()
                count = 0
                portsCount = 0
                vulnCount = 0
                categoryCount =0
                if result['is_malicious'] == True:
                    count += 1
                    print("[+] Malicious IP:", result['is_malicious'])
                    print('[+] VPN:',result['is_vpn'])
                    print('[+] Remote access:', result['can_remote_access'])
                    print('[+] Remote port:', result['remote_port'])
                    print('[+] IDS:', result['ids'])
                    if result['current_opened_port']['count'] != 0:
                        print('[+] Count of opened ports:', result['current_opened_port']['count'])
                    for key in range(len(result['current_opened_port']['data'])):
                        portsCount += 1
                        print('\t-',
                            result['current_opened_port']['data'][key]['socket_type'],
                            result['current_opened_port']['data'][key]['port'],
                            result['current_opened_port']['data'][key]['protocol'],
                            result['current_opened_port']['data'][key]['product_name'],
                            result['current_opened_port']['data'][key]['product_version'],
                            result['current_opened_port']['data'][key]['has_vulnerability']
                        )
                    if result['vulnerability']['count'] != 0:
                        vulnCount += 1
                        print('[+] Count of vulnerabilities founded:',result['vulnerability']['count'])
                        charToRemove = ["{", "}", "[", "]"]
                        stringToDisplay = str(result['vulnerability']['data'][key]['ports']).replace("'", '')
                        for key in range(len(result['vulnerability']['data'])):
                            for char in charToRemove:
                                stringToDisplay = stringToDisplay.replace(char, "")
                            print('\t-',
                                result['vulnerability']['data'][key]['cve_id'],
                                stringToDisplay,
                                #result['vulnerability']['data'][key][["cvssv2_vector"]],  # TypeError: unhashable type: 'list'
                                result['vulnerability']['data'][key]['cvssv2_score'],
                                result['vulnerability']['data'][key]['cvssv3_score'],
                                result['vulnerability']['data'][key]['product_version'],
                                result['vulnerability']['data'][key]['product_vendor']
                            )
                    else:
                        vulnCount == vulnCount
                    if result['ip_category']['count'] != 0:
                        print('[+] count of IP category: ', result['ip_category']['count'])
                        for key in range(len(result['ip_category']['data'])):
                            categoryCount += 1
                            print('\t- IP category:',
                                result['ip_category']['data'][key]['type'],'\n\t\t+ detected source =>',
                                result['ip_category']['data'][key]['detect_source']
                            )
                    else:
                        categoryCount == categoryCount
                else:
                    count == count
                    portsCount == portsCount
                    print(DOMAIN_NAME_TO_IP, 'Not found in CriminalIP.io')
            global CRIMINALIP_COUNTS
            CRIMINALIP_COUNTS = [count, portsCount, result['vulnerability']['count'], categoryCount]  # optimise without calculation, take result[][]
        except Exception:
            print(Color.RED + "[!] Error with CriminalIP config, check it" + Color.END)
        
        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n --------------------------------- ")
            fileReport.write("\n Criminal IP report:")
            fileReport.write("\n --------------------------------- \n")
            if count != 0:
                fileReport.write('[!] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(' Is considered malicious')
            if count == 0:
                fileReport.write('[+] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(" Not considered malicious by Criminal IP")
                fileReport.close()


    @staticmethod
    def abuseIPDB():
        try:
            print(Color.GREEN + "[+] AbuseIPDB report:" + Color.END)
            with open(KEY_FILE, "r") as file:
                configFile = json.load(file)
                url = "https://api.abuseipdb.com/api/v2/check"
                querystring = {'ipAddress': DOMAIN_NAME_TO_IP, 'maxAgeInDays': '90'}
                headers = {'Accept': 'applications/json', 'key': configFile['api']['abuseipdb']}
                response = requests.request(method='GET', url=url, headers=headers, params=querystring)
                if response.status_code == 200:
                    result = response.json()
                    print('[+] Count of reports:', result['data']['totalReports'])
                    print(
                        '\t- Whiteliested:', result['data']["isWhitelisted"],
                        '\n\t- Confidence in %:', result['data']["abuseConfidenceScore"],
                        '\n\t- Country code:', result['data']["countryCode"], 
                        '\n\t- ISP:', result['data']["isp"], 
                        '\n\t- Domain:', result['data']["domain"], 
                        '\n\t- Is TOR node:', result['data']["isTor"], 
                        '\n\t- Distinct users:', result['data']["numDistinctUsers"], 
                        '\n\t- Last report date:', result['data']["lastReportedAt"]
                    )
            global ABUSEIPDB_CONFIDENCE
            ABUSEIPDB_CONFIDENCE = [result['data']['totalReports'], result['data']["abuseConfidenceScore"]]
        except Exception:
            print(Color.RED + "[!] Error with AbuseIPDB config, check it" + Color.END)

        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n --------------------------------- ")
            fileReport.write("\n AbuseIPDB report:")
            fileReport.write("\n --------------------------------- \n")
            if result['data']['totalReports'] != 0:
                fileReport.write('[!] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(' Is reported on AbuseIPDB')
            if result['data']['totalReports'] == 0:
                fileReport.write('[+] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(" Not reported on AbuseIPDB")
                fileReport.close()


    @staticmethod
    def otx():
        try:
            print(Color.GREEN + "[+] OTX report:" + Color.END)
            with open(KEY_FILE, "r") as file:
                configFile = json.load(file)
                otx = OTXv2(configFile['api']['otx'])
                response = otx.get_indicator_details_full(IndicatorTypes.IPv4, DOMAIN_NAME_TO_IP)
                print("[+] Whois link:", response['general']['whois'])
                print("[+] Reputation:", response['general']['reputation'])
                #print("indicators: ", response['general']['base_indicator'])
                print("[+] Count of pulses reported:", response['general']['pulse_info']['count'])
                global OTX_COUNT
                OTX_COUNT = response['general']['pulse_info']['count']
                if response['general']['pulse_info']['count'] != 0:
                    for key in range(len(response['general']['pulse_info']['pulses'])):
                        whileCount = response['general']['pulse_info']['count']
                        tags = str(response['general']['pulse_info']['pulses'][key]['tags'])
                        charToRemove = ["[", "]", "'"]
                        if response['general']['pulse_info']['pulses'][key]['tags'] != []:
                            while whileCount <= 25:
                                for char in charToRemove:
                                    tags = tags.replace(char, '')
                                print("[+] 5 lasts puples containing tags: ")
                                print(
                                    '\t- Description:', response['general']['pulse_info']['pulses'][key]['description'],
                                    '\n\t- Last update:', response['general']['pulse_info']['pulses'][key]['modified'],
                                    '\n\t- Tags:',tags
                                )
                                if whileCount == 5:
                                    break
                                whileCount = whileCount + 1
        except Exception:
            print('Not found in otx alien vault!')

        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n --------------------------------- ")
            fileReport.write("\n OTX report:")
            fileReport.write("\n --------------------------------- \n")
            if response['general']['pulse_info']['count'] != 0:
                fileReport.write('[!] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(' Is reported on OTX')
            if response['general']['pulse_info']['count'] == 0:
                fileReport.write('[+] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(" Not reported on OTX")
            fileReport.close()


    @staticmethod
    def othersScans():
        print('')
        # https://github.com/stamparm/ipsum/tree/master


class Reputation:
    """_summary_
    Sends constants to summary class
    """
    @staticmethod
    def vtCount():
        return VT_COUNT    
    
    @staticmethod
    def dtCount():
        return DUGGY_COUNT
    
    @staticmethod
    def ciCount():
        return CRIMINALIP_COUNTS 
    
    @staticmethod
    def abCount():
        return ABUSEIPDB_CONFIDENCE

    @staticmethod
    def otCount():
        return OTX_COUNT
