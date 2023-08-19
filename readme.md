# Readme


> ## **Discovers an IP and/or domain from the following web applications and returns a reputation score.**
> ### **V1, Started in July 23, tipio, SOC Analyst Intern and Shyan / based on the example of [Sooty](https://github.com/TheresAFewConors/Sooty/blob/master/Sooty.py)**


## In run:
- [VirusTotal](https://www.virustotal.com/gui/home/search)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [Duggy Tuxy blacklist](https://github.com/duggytuxy/malicious_ip_addresses)
- [IPsum](https://github.com/stamparm/ipsum)
- [CriminalIP](https://www.criminalip.io/en)
- [OTX/AlienVault](https://otx.alienvault.com/) 


## Setup
### Requirements:
- OTXv2:
```bash
cd ../analyzer
pip --version  # need pip3
pip install OTXv2
# If not accessible after common installation via pip 
# try:
pip3 install OTXv2
# or
sudo pip install OTXv2
```

### Adjust utils.py:
- Create the key_file.json file. 
- Set the correct path for the key_file.json file in the KEY_FILE constante of `utils.py`.
    - Default: `"/home/keys_file.json"`

```json
{
    "api": {
        "virus total": "your API key", 
        "abuseipdb": "your API key",
        "criminal ip": "your API key",
        "otx": "your API key"
    }
}     
```

### Create an alias:
- edit your `.bashrc` or `.zshrc`
```bash
alias analyzer='path of main.py directory'
source .zshrc
```

### Run analyzer:
```bash
analyzer
Enter IP Address or Domain name: 
```

## Coming soon: