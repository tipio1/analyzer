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
import PyPDF2
from os.path import exists
from utils import *


# Analysis functions:
class Functions:
    @staticmethod
    def whois():
        """_summary_
        Check ip2location and return the results in a dedicated file in the reports directory.
            whois cmd sup:
                or
                os.system("whois " + IP + " | grep -A15 netname | grep -E 'NetName|Organization|Country|RegDate' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u > " + f"analyzer_reports/{DOMAIN_NAME_TO_IP}_whois.txt")
        """
        print(Color.GREEN + "[+] ip2location report: " + Color.END)
        global WHOIS
        
        with open(KEY_FILE, 'r') as file:
            configFile = json.load(file)
            key = configFile['api']['ip2location']
            url = (f"https://api.ip2location.io/?key={key}&ip={DOMAIN_NAME_TO_IP}&format=json")
            response = requests.request("GET", url)
            result = response.json()
            print('\t- Country code:', result['country_code'],
                  '\n\t- Country name:', result['country_name'],
                  '\n\t- Time zone:', result['time_zone'],
                  '\n\t- Categorized as public proxy:', result['is_proxy'])

        print(Color.ORANGE + "[+] Potential more infos stored in the report file (whois)" + Color.END)
        char = ("a" or "b" or "c" or "d" or "e" or "f" or "g" or "h" or "i" or "j" or "k" or "l" or "m" or "n" or "o" or "p" or "q" or "r" or "s" or "t" or "u" or "v" or "w" or "x" or "y" or "z")
        if char in str(INPUT):
            os.system("whois " + IP + " | grep -E 'Registrar WHOIS Server|Name Server|Creation Date|Registrar URL|Registrar Registration Expiration Date|Registrant Organization|Registrant Country|Name Server' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u > " + f"analyzer_reports/{DOMAIN_NAME_TO_IP}_whois.txt")
        else:
            os.system("whois " + IP + " | grep -A15 netname | grep -E 'netname|country|person|route|last-modified' | sed -e 's/^\ *//g' -e 's/\  */ /g' | tr '[A-Z]' '[a-z]' | sort -u > " + f"analyzer_reports/{DOMAIN_NAME_TO_IP}_whois.txt")

        isProxy = str(result['is_proxy'])
        WHOIS = [result['country_name'], isProxy]

        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n ------------------------------------------------------------------ ")
            fileReport.write("\n ip2location report:")
            fileReport.write("\n --------------------------------- \n")
            fileReport.write('\t- Country code: ')
            fileReport.write(result['country_code'])
            fileReport.write('\n\t- Country name: ')
            fileReport.write(result['country_name'])
            fileReport.write('\n\t- Time zone: ')
            fileReport.write(result['time_zone'])
            fileReport.write('\n\t- Categorized as public proxy: ')
            fileReport.write(isProxy)
            with open((f"analyzer_reports/{DOMAIN_NAME_TO_IP}_whois.txt"), 'r') as whoisFile:
                fileReport.write("\n --------------------------------- ")
                fileReport.write("\n Whois report:")
                fileReport.write("\n --------------------------------- \n")
                fileReport.write(str(whoisFile.read()))
                fileReport.close()
                os.system(f'rm -rf analyzer_reports/{DOMAIN_NAME_TO_IP}_whois.txt')


    @staticmethod
    def virusTotal():
        """_summary_
        Check VT and return the results in a dedicated file in the reports directory.
        """
        try:
            print(Color.GREEN + "[+] VirusTotal report:" + Color.END)
            global VT_COUNT
            
            with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
                fileReport.write("\n ------------------------------------------------------------------ ")
                fileReport.write("\n VirusTotal report:")
                fileReport.write("\n --------------------------------- \n")

                with open(KEY_FILE, "r") as file:
                    configFile = json.load(file)
                    url = 'https://www.virustotal.com/vtapi/v2/url/report'
                    params = {'apikey': configFile['api']['virus total'], 'resource': DOMAIN_NAME_TO_IP}
                    response = requests.get(url, params=params)
                    result = response.json()
                    count = 0
                    
                    if 'Resource does not exist in the dataset' in str(result):
                        print(Color.ORANGE + '[!] Message:' + result['verbose_msg'] + Color.END)
                        VT_COUNT = [0, 0]

                    elif response.status_code == 200:
                        fileReport.write(result['permalink'])
                        fileReport.write("\n --------------------------------- \n")
                        if result['positives'] == 0:
                            print("[!] No positives results found in " + str(result['total']) + " AV scanned")
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
                                    fileReport.write(stringToDisplay)
                                else:
                                    count == count

                            print(Color.GREEN + "[+] Number of detections: ", str(count) + Color.END)
                            fileReport.write("\n --------------------------------- \n")
                            fileReport.write('Number of detections: ')
                            fileReport.write(str(count))
                            fileReport.close()
                            VT_COUNT = [count, result['total']]

        except Exception as err:
            print(Color.RED + "[!] Error with Virus Total: " + err + Color.END)

  
    @staticmethod
    def scrapDuggyTuxyRepo():
        """
        These are the IP addresses of the most active Botnets/Zombies/Scanners in European Cyber Space
        """
        try:
            print(Color.GREEN + "[+] Duggy Tuxy report:" + Color.END)
            global DUGGY_COUNT

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
            
            DUGGY_COUNT = count
        
        except Exception as err:
            print(Color.RED + "[!] Error with Duggy Tuxy's list: " + err + Color.END)
        
        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n ------------------------------------------------------------------ ")
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
    def ipsum():
        """
        IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses like:
            abuseipdb, alienvault, atmos, badips, bitcoinnodes, blocklist, botscout, cobaltstrike, malwaredomains, proxylists, ransomwaretrackerurl, talosintelligence, torproject, etc.
        """
        try:
            print(Color.GREEN + "[+] IPsum report:" + Color.END)
            global IPSUM_COUNT

            count = 0
            blacklists = 0
            url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
            page = urllib.request.urlopen(url,timeout=5).read()
            soup = bs(page, 'html.parser')
            text = soup.get_text()

            if DOMAIN_NAME_TO_IP in str(text):
                count += 1
                print('[!]', DOMAIN_NAME_TO_IP, 'Found in the list.')
                os.system(f'curl --compressed https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v "#" | grep {DOMAIN_NAME_TO_IP} | cut -f 2 > out.txt')

                with open('out.txt', 'r') as blacklisted:
                    blacklists = blacklisted.read()
                    if int(blacklists) != 0:
                        print(f'[!] {DOMAIN_NAME_TO_IP} founded in:', int(blacklists),'blacklists')
                        blacklisted.close()
                        os.system('rm -rf out.txt')

            else:
                count == count
                blacklists = blacklists
                print('[+]', DOMAIN_NAME_TO_IP, "Not found in the IPsum's blacklists")
            
            IPSUM_COUNT = [count, int(blacklists)]

        except Exception as err:
            print(Color.RED + "[!] Error with IPsum's blacklists: "+ err + Color.END)

        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n ------------------------------------------------------------------ ")
            fileReport.write("\n IPsum report:")
            fileReport.write("\n --------------------------------- \n")
            if count != 0:
                fileReport.write('[!] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(f' Found in {int(blacklists)} blacklists.')
            if count == 0:
                fileReport.write('[+] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(" Not found in the IPsum's blacklists")
                fileReport.close()


    @staticmethod
    def criminalIP():
        try:
            print(Color.GREEN + "[+] Criminal IP report:" + Color.END)
            global CRIMINALIP_COUNTS

            url = (f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={DOMAIN_NAME_TO_IP}")
            payload = {}
            
            with open(KEY_FILE, "r") as file:
                configFile = json.load(file)
                headers = {'x-api-key': configFile['api']['criminal ip']}
                response = requests.request("GET", url, headers=headers, data=payload)
                result = response.json()
                count = 0
                
                if result['is_malicious'] == True:
                    count += 1
                    print("[+] Malicious IP:", result['is_malicious'],
                          '\n[+] VPN:',result['is_vpn'],
                          '\n[+] Remote access:', result['can_remote_access'],
                          '\n[+] Remote port:', result['remote_port'],
                          '\n[+] IDS:', result['ids'])

                    if result['current_opened_port']['count'] != 0:
                        print('[+] Count of opened ports:', result['current_opened_port']['count'])
                        portsCount = 0

                        for key in range(len(result['current_opened_port']['data'])):
                            if (result['current_opened_port']['count'] <= 10 or result['current_opened_port']['count'] > 10):
                                if result['current_opened_port']['data'][key]['has_vulnerability'] == True:
                                    print('\t-',
                                        result['current_opened_port']['data'][key]['socket_type'],
                                        result['current_opened_port']['data'][key]['port'],
                                        result['current_opened_port']['data'][key]['protocol'],
                                        result['current_opened_port']['data'][key]['product_name'],
                                        result['current_opened_port']['data'][key]['product_version'],
                                        result['current_opened_port']['data'][key]['has_vulnerability'])
                                    portsCount = portsCount + 1
                                    if portsCount == 10:
                                        break

                    if result['vulnerability']['count'] != 0:
                        print('[+] Count of vulnerabilities founded:',result['vulnerability']['count'])
                        charToRemove = ["{", "}", "[", "]"]
                        vulCount = 0

                        for key in range(len(result['vulnerability']['data'])):
                            stringToDisplay = str(result['vulnerability']['data'][key]['ports']).replace("'", '')
                            if (result['vulnerability']['count'] <= 10 or result['vulnerability']['count'] > 10):
                                for char in charToRemove:
                                    stringToDisplay = stringToDisplay.replace(char, "")
                                print('\t-',
                                    result['vulnerability']['data'][key]['cve_id'],
                                    result['vulnerability']['data'][key]['cvssv2_score'],
                                    result['vulnerability']['data'][key]['cvssv3_score'],
                                    result['vulnerability']['data'][key]['product_version'],
                                    result['vulnerability']['data'][key]['product_vendor'])
                                vulCount = vulCount + 1
                                if vulCount == 10:
                                    break

                    if result['ip_category']['count'] != 0:
                        print('[+] count of IP category: ', result['ip_category']['count'],
                              '\n[+] IP category:')
                        for key in range(len(result['ip_category']['data'])):
                            print('\t-', result['ip_category']['data'][key]['type'])

                else:
                    count == count
                    print(DOMAIN_NAME_TO_IP, 'Not found in CriminalIP.io')
            
            CRIMINALIP_COUNTS = [count, result['current_opened_port']['count'], result['vulnerability']['count'], result['ip_category']['count']]
        
        except Exception as err:
            print(Color.RED + "[!] Error with CriminalIP: " + err + Color.END)
        
        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n ------------------------------------------------------------------ ")
            fileReport.write("\n Criminal IP report:")
            fileReport.write("\n --------------------------------- \n")
            if count != 0:
                fileReport.write('[!] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(' Is considered malicious')
                fileReport.write('\n[!] Count of opened ports: ')
                fileReport.write(str(result['current_opened_port']['count']))
                fileReport.write('\n[!] Count of vulnerabilities: ')
                fileReport.write(str(result['vulnerability']['count']))
            if count == 0:
                fileReport.write('[+] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(" Not considered malicious by Criminal IP")
                fileReport.close()


    @staticmethod
    def abuseIPDB():
        try:
            print(Color.GREEN + "[+] AbuseIPDB report:" + Color.END)
            global ABUSEIPDB_CONFIDENCE
            
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
                        '\n\t- Last report date:', result['data']["lastReportedAt"])
            
            ABUSEIPDB_CONFIDENCE = [result['data']['totalReports'], result['data']["abuseConfidenceScore"]]
        
        except Exception as err:
            print(Color.RED + "[!] Error with AbuseIPDB:" + err + Color.END)

        with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
            fileReport.write("\n ------------------------------------------------------------------ ")
            fileReport.write("\n AbuseIPDB report:")
            fileReport.write("\n --------------------------------- \n")
            if result['data']['totalReports'] != 0:
                fileReport.write('[!] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(' Is reported on AbuseIPDB')
                fileReport.write('\n[!] Count of reports: ')
                fileReport.write(str(result['data']['totalReports']))
                fileReport.write('\n[!] Confidence (in %): ')
                fileReport.write(str(result['data']["abuseConfidenceScore"]))
                fileReport.write('\n[!] Last report date: ')
                fileReport.write(str(result['data']["lastReportedAt"]))
            if result['data']['totalReports'] == 0:
                fileReport.write('[+] ')
                fileReport.write(DOMAIN_NAME_TO_IP)
                fileReport.write(" Not reported on AbuseIPDB")
                fileReport.close()


    @staticmethod
    def otx():
        try:
            print(Color.GREEN + "[+] OTX report:" + Color.END)
            global OTX_COUNT
            
            with open(KEY_FILE, "r") as file:
                configFile = json.load(file)
                otx = OTXv2(configFile['api']['otx'])
                response = otx.get_indicator_details_full(IndicatorTypes.IPv4, DOMAIN_NAME_TO_IP)

                print("[+] Reputation:", response['general']['reputation'],
                      "\n[+] Count of pulses reported:", response['general']['pulse_info']['count'])
                
                OTX_COUNT = response['general']['pulse_info']['count']
                
                if response['general']['pulse_info']['count'] != 0:
                    print("[+] Last puple containing tags: ")
                    tagCount = 0

                    for key in range(len(response['general']['pulse_info']['pulses'])):
                        tags = str(response['general']['pulse_info']['pulses'][key]['tags'])
                        charToRemove = ["[", "]", "'"]
                        if response['general']['pulse_info']['pulses'][key]['tags'] != []:
                            for char in charToRemove:
                                tags = tags.replace(char, '')
                            print(
                                '\t- Description:', response['general']['pulse_info']['pulses'][key]['description'],
                                '\n\t- Last update:', response['general']['pulse_info']['pulses'][key]['modified'],
                                '\n\t- Tags:',tags,
                                '\n')
                            if tagCount == 1:
                                break
                            tagCount = tagCount + 1
        
        except Exception as err:
            print(Color.RED + "[!] Error with OTX:" + err + Color.END)
            OTX_COUNT = 0
        
        try:
            with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
                fileReport.write("\n ------------------------------------------------------------------ ")
                fileReport.write("\n OTX report:")
                fileReport.write("\n --------------------------------- \n")

                if response['general']['pulse_info']['count'] != 0:
                    fileReport.write('[!] ')
                    fileReport.write(DOMAIN_NAME_TO_IP)
                    fileReport.write(' Is reported on OTX')
                    fileReport.write("\n[+] Whois link: ")
                    fileReport.write(response['general']['whois'])
                    fileReport.write('\n[!] Count of pulses: ')
                    fileReport.write(str(response['general']['pulse_info']['count']))
                    fileReport.write('\n[!] OTX link: ')
                    fileReport.write(f'https://otx.alienvault.com/indicator/ip/{DOMAIN_NAME_TO_IP}')
                if response['general']['pulse_info']['count'] == 0:
                    fileReport.write('[+] ')
                    fileReport.write(DOMAIN_NAME_TO_IP)
                    fileReport.write(" Not reported on OTX")
                fileReport.close()
        except Exception as err:
            with open('analyzer_reports/'+TODAY+'/'+str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
                fileReport.write('Not found in OTX Alien vault!')
                fileReport.close()
            print(Color.RED + "[!] Error with OTX:" + err + Color.END)


    @staticmethod
    def othersScans():
        print('')
        # https://threatbook.io/


class Country:
    @staticmethod
    def gci():
        """_summary_
            The Global Cybersecurity Index (GCI): trusted reference that measures the commitment of countries to cybersecurity at a global level
        """
        print(Color.GREEN + "[+] Global Cybersecurity Index (GCI) report: a reliable benchmark measuring countries' commitment to cybersecurity worldwide" + Color.END)
        print('[+] Published in Geneva, Switerland 2023',
              '\n[+] Legend (Country name - Note - Rank):',
              '\n\t- * no data collected',
              '\n\t- ** no response to the questionnaire',
              '\n')

        country = WHOIS[0]
        os.system(f"cat cgi.txt | grep '{country}'")


class Count:
    """_summary_
    Sends constants to summary class
    """
    @staticmethod
    def count():
        return [WHOIS, VT_COUNT, DUGGY_COUNT, IPSUM_COUNT,CRIMINALIP_COUNTS, ABUSEIPDB_CONFIDENCE, OTX_COUNT]