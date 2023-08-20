# coding: utf-8
"""_summary_
V1, July 23, tipio, SOC Analyst Intern and Shyan / based on the example of Sooty
Summary function
"""


from analyzer import *
from utils import *


class Summary:
    """_summary_
    Calculates scores and returns results
    """
    @staticmethod
    def summary():
        try:
            gciNote = Count.count()[7][0]
            gciRank = Count.count()[7][1]
            country = Count.count()[0][0]
            prx = Count.count()[0][1]
            vt = Count.count()[1][0]
            vtTotalScanners = Count.count()[1][1]
            dt = Count.count()[2]
            ipsum = Count.count()[3][0]
            ipsumCount = Count.count()[3][1]
            ciCount = Count.count()[4][0]
            ciPortCount = Count.count()[4][1]
            ciVulCount = Count.count()[4][2]
            ciCatCount = Count.count()[4][3]
            abReports = Count.count()[5][0]
            abCnfidence = Count.count()[5][1]
            ot = Count.count()[6]

            agressivity = 0
            malicious = 0
            reported = 0

            print('[+] Country:',str(country),
                  '\n[+] Categorized as public proxy (ip2location):',str(prx),
                  '\n[+] Country rank:', gciRank,
                  '\n[+] GCI report note:', gciNote)
            print("--------------------------------------------------------------------------------------------------------")
            
            if (vt == 0):
                print('[+] Clean on Virus Total')
            else:
                print("[!] Detected on Virus Total",
                      '\n\t- Count of detections:', vt,
                      '\n\t- Count of Antivirus scanned:', vtTotalScanners)
            print("--------------------------------------------------------------------------------------------------------")
            
            if (dt == 0):  # integrate other blacklists to adjust the result
                print("[+] Not in Duggy Tuxy's list")
                agressivity = 2
            if (ipsum == 0):
                print("[+] Not in IPsum's blacklists")
                agressivity = 2
            else:
                print("[!] Found in Duggy Tuxy and/or IPsum lists")
                if (dt == 1 and vt <= 8):
                    agressivity = 4
                if (dt == 1 and vt >= 8 and vt <= 15):
                    agressivity = 6
                if (dt == 1 and vt >= 16 and vt <= 25):
                    agressivity = 8
                if (dt == 1 and vt >= 26):
                    agressivity = 10
                if (ipsum == 1 and ipsumCount <= 3):
                    agressivity = 4
                if (ipsum == 1 and vt >= 8 and ipsumCount > 3 and  ipsumCount < 5):
                    agressivity = 6
                if (ipsum == 1 and vt >= 16 and ipsumCount > 5 and  ipsumCount < 7):
                    agressivity = 8
                if (ipsum == 1 and ipsumCount > 7):
                    agressivity = 10
                if (dt == 1 and ipsum == 1 and vt <= 3 and ipsumCount < 2):
                    agressivity = 4
                if (dt == 1 and ipsum == 1 and vt > 4 and ipsumCount > 2 and ipsumCount < 4):
                    agressivity = 6
                if (dt == 1 and ipsum == 1 and vt > 6 and ipsumCount > 4 and ipsumCount < 8):
                    agressivity = 8
                if (dt == 1 and ipsum == 1 and vt > 6 and ipsumCount >= 8):
                    agressivity = 10
                print('[!] Agressivity:', agressivity)
            print("--------------------------------------------------------------------------------------------------------")
            
            if ciCount == 0:
                print('[+] Not reporteded by Criminal IP')
            else:
                print("[!] Reported malicious on Criminal IP",
                      "\n\t- Count of opened ports:",ciPortCount,
                      "\n\t- Count of vulnerability founded:",ciVulCount,
                      "\n\t- Count of IP category:",ciCatCount)
                if (ciCount == 1 and agressivity <= 4):
                    malicious = 4
                if (ciCount == 1 and agressivity > 4 and agressivity <= 6):
                    malicious = 6
                if (ciCount == 1 and agressivity > 6 and agressivity <= 8):
                    malicious = 8
                if (ciCount == 1 and agressivity > 8):
                    malicious = 10
                print('[!] Malicious:', malicious)
            print("--------------------------------------------------------------------------------------------------------")
            
            if abReports == 0:  # integrate otx to adjust the result
                print("[+] Not found on AbuseIPDB")
            else:
                print("[!] Reported on AbuseIPDB",
                    "\n\t- Confidence index:",abCnfidence, '%',
                    "\n\t- Count of reports:",abReports)
                if (abReports <= 50 and agressivity < 4 and malicious <= 4):
                    reported = 4
                if (abReports >= 50 and agressivity <= 6 and malicious <= 6):
                    reported = 6
                if (abReports >= 50 and agressivity <= 8 and malicious <= 8):
                    reported = 8     
                if (abReports >= 50 and agressivity > 8 and malicious > 8):
                    reported = 10
                print('[!] Reported:', reported)
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
        
        except Exception as err:
            print('error:', err)
