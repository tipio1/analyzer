# Readme

> **Discovers an IP and/or domain from the following web applications and returns a reputation score.**
>
> **V1, July 23, tipio, SOC Analyst Intern and Shyan / based on the example of [Sooty](https://github.com/TheresAFewConors/Sooty/blob/master/Sooty.py)**

### In run:
- VirusTotal
- AbuseIPDB 
- [Duggy Tuxy blacklist](https://github.com/duggytuxy/malicious_ip_addresses/blob/main/botnets_zombies_scanner_spam_ips.txt) 
- CriminalIP
- OTX/AlienVault 

### Coming soon:



## Setup
### Adjust utils.py:
- Create the key_file.json file. 
- Set the correct path for the key_file.json file in the KEY_FILE constante of `utils.py`.
    - Default: "/home/keys_file.json"

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