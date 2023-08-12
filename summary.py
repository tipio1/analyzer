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
    Parse functions, calculate note score and returns results
            print('[!] Agressivity:',agressivity)
            print('[!] Malicious:',malicious)
            print('[!] reported:',reported)
            counts = [ciCount, ciPortCount, ciVulCount, ciCatCount]
            print(
                "\t-",vt,
                "\n\t-",vtTotalScanners,
                "\n\t-",dt,
                "\n\t-",ciCount,
                "\n\t-",ciPortCount,
                "\n\t-",ciVulCount,
                "\n\t-",ciCatCount,
                "\n\t-",abReports,
                "\n\t-",abCnfidence,
                "\n\t-",ot
            )
            print(
                "\t-",vtAverage,
                "\n\t-",agressivity,
                "\n\t-",malicious,
                "\n\t-",reported
            )
    """
    @staticmethod
    def summary():
        try:
            country = Count.count()[0][0]
            prx = Count.count()[0][1]
            vt = Count.count()[1][0]
            vtTotalScanners = Count.count()[1][1]
            dt = Count.count()[2]
            ciCount = Count.count()[3][0]
            ciPortCount = Count.count()[3][1]
            ciVulCount = Count.count()[3][2]
            ciCatCount = Count.count()[3][3]
            abReports = Count.count()[4][0]
            abCnfidence = Count.count()[4][1]
            ot = Count.count()[5]
            
            if vt == 0 and vtTotalScanners == 0:
                vtAverage = 0
            else:
                vtAverage = round((vt/vtTotalScanners), 2)

            agressivity = 0
            malicious = 0
            reported = 0

            print('[+] Country: ',str(country))
            print('[+] Categorized as proxy: ',str(prx))
            print("--------------------------------------------------------------------------------------------------------")
            
            if (vt == 0):
                print('[+] Clean on Virus Total')
            else:
                print("[!] Detected on Virus Total")
                print('\t- Count of detections:', vt,
                      '\n\t- Count of Antivirus scanned:', vtTotalScanners,
                      '\n\t- Virus Total Average:',vtAverage
                    )
            print("--------------------------------------------------------------------------------------------------------")
            
            if (dt == 0):  # integrate other blacklists to adjust the result
                print("[+] Not in Duggy Txy's list")
                agressivity = 2
            else:
                print("[!] In Duggy Txy's list")
                if (dt == 1 and vt <= 8):
                    agressivity = 4
                if (dt == 1 and vt >= 8 and vt <= 15):
                    agressivity = 6
                if (dt == 1 and vt >= 16 and vt <= 25):
                    agressivity = 8
                if (dt == 1 and vt >= 26):
                    agressivity = 10
            print("--------------------------------------------------------------------------------------------------------")
            
            if ciCount == 0:
                print('[+] Not reporteded by Criminal IP')
            else:
                print("[!] Reported malicious on Criminal IP")
                print(
                      "\t- Count of opened ports:",ciPortCount,
                      "\n\t- Count of vulnerability founded:",ciVulCount,
                      "\n\t- Count of IP category:",ciCatCount
                    )
                if (ciCount == 1 and agressivity <= 4):
                    malicious = 4
                if (ciCount == 1 and agressivity > 4 and agressivity <= 6):
                    malicious = 6
                if (ciCount == 1 and agressivity > 6 and agressivity <= 8):
                    malicious = 8
                if (ciCount == 1 and agressivity > 8):
                    malicious = 10
            print("--------------------------------------------------------------------------------------------------------")
            
            if abReports == 0:  # integrate otx to adjust the result
                print("[+] Not found on AbuseIPDB")
            else:
                print("[!] Reported on AbuseIPDB")
                print(
                    "\t- Confidence index:",abCnfidence, '%',
                    "\n\t- Count of reports:",abReports)
                if (abReports <= 50 and agressivity < 4 and malicious <= 4):
                    reported = 4
                if (abReports >= 50 and agressivity <= 6 and malicious <= 6):
                    reported = 6
                if (abReports >= 50 and agressivity <= 8 and malicious <= 8):
                    reported = 8     
                if (abReports >= 50 and agressivity > 8 and malicious > 8):
                    reported = 10
            print("--------------------------------------------------------------------------------------------------------")
            
            if ot == 0:
                print("[+] No pulses reported on OTX")
            else:
                print("[!] Count of pulses reported on OTX:",ot)
            print("--------------------------------------------------------------------------------------------------------")
            
            note = (agressivity+malicious+reported)/3
            print("[!] General note:", round(note, 2))
            if round(note, 2) <= 2:
                print(Color.GREEN + '[!] Low IP' + Color.END)
            if (round(note, 2) > 2 and round(note, 2) < 6):
                print(Color.ORANGE + '[!] Medium IP' + Color.END)
            if (round(note, 2) >= 6 and round(note, 2) < 8):
                print(Color.RED + '[!] High IP' + Color.END)
            if round(note, 2) >= 8:
                print(Color.RED + '[!] Critical IP' + Color.END)
        
        except Exception:
            print('error')
