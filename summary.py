# coding: utf-8
"""_summary_
V1, July 23, tipio, SOC Analyst Intern and Shyan / based on the example of Sooty
Summary function
"""

from analyzer import *
from utils import *
# import sys



class Summary:
    """_summary_
    Parse functions, calculate reputation score and returns results
            print('[!] Agressivity:',agressivity)
            print('[!] Malicious:',malicious)
            print('[!] Suspect:',suspect)
    """
    @staticmethod
    def summary():
        try:
            vt = Reputation.vtCount()[0]
            vtTotalScanners = Reputation.vtCount()[1]
            dt = Reputation.dtCount()
            ciCount = Reputation.ciCount()[0]
            ciPortCount = Reputation.ciCount()[1]
            ciVulCount = Reputation.ciCount()[2]
            ciCatCount = Reputation.ciCount()[3]
            counts = [ciCount, ciPortCount, ciVulCount, ciCatCount]
            abReports = Reputation.abCount()[0]
            abCnfidence = Reputation.abCount()[1]
            ot = Reputation.otCount()

            if (vt == 0):
                print('[+] Clean on Virus Total')
                print("[+] IP or Domain not reported")
                exit(0)
            else:
                average = vt/vtTotalScanners
                print("[!] Detected on Virus Total")
                print('\t- Count of detections:', vt,
                      '\n\t- Count of Antivirus scanned:', vtTotalScanners,
                      '\n\t- Virus Total Average:',round(average, 2)
                    )
            if dt == 0:
                print("[+] Not in Duggy Txy's list")
            else:
                print("[!] In Duggy Txy's list")
            if (dt == 0, average <= 0.09, ot >= 5):
                agressivity = 4
            elif (dt == 0, average > 0.09, ot >= 10):
                agressivity = 6
            elif (dt == 1, average > 0.09, ot >= 10):
                agressivity = 8
            elif (dt == 1, average > 0.09, ot >= 10):
                agressivity = 10
            print("--------------------------------------------------------------------------------------------------------")
            # print(counts)
            if ciCount == 0:
                print('[+] Not suspected by Criminal IP')
            else:
                print("[!] Reported malicious on Criminal IP")
                print(
                      "\t- Count of opened ports:",ciPortCount,
                      "\n\t- Count of vulnerability founded:",ciVulCount,
                      "\n\t- Count of IP category:",ciCatCount
                    )
            if (agressivity <= 6, average <= 0.09, ciCount == 0):
                malicious = 5
            elif (agressivity >= 7, average > 0.09, ciCount == 1):
                malicious = 10
            print("--------------------------------------------------------------------------------------------------------")
            if abReports == 0:
                print("[+] Not found on AbuseIPDB")
            else:
                print("[!] Reported on AbuseIPDB")
                print(
                    "\t- Confidence index:",abCnfidence, '%',
                    "\n\t- Count of reports:",abReports)     
            if (malicious > 6, abCnfidence > 50, average >= 0.09, agressivity <= 6):
                suspect = 8
            elif (malicious > 6, abCnfidence > 60, average >= 0.09, agressivity >= 6):
                suspect = 10
            print("--------------------------------------------------------------------------------------------------------")
            if ot == 0:
                print("[+] No pulses reported on OTX")
            else:
                print("[!] Count of pulses reported on OTX:",ot)
            print("--------------------------------------------------------------------------------------------------------")
            note = (agressivity+malicious+suspect)/3
            print("[!] General note:", round(note, 2))
            if round(note, 2) <= 6:
                print('[!] Medium IP')
            elif round(note, 2) >= 7:
                print('[!] High IP')
            elif round(note, 2) > 8:
                print('[!] Critical IP')
        except Exception:
            print('error')
