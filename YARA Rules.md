# What are YARA rules?
**YARA rules** are set of patterns to identify files written in YARA language.

### Use Cases
* As an analyst you found a malicious file (for example: "ransomware") and you want to sweep the environment to check if it exists elsewhere.
* As an analyst you want to sweep the environment for a new malware campaign IOCs, some YARA rules found here: https://github.com/Neo23x0/signature-base/tree/master/yara

### Create a YARA rule

```
1- create a YARA rule .yar/.yara file
2- run pattern matching tool
```
![image](https://github.com/BL4CKC0FF33/WriteUps/assets/69141453/135213cb-1c66-455c-b16e-1ba9a2188eaa)

By analyzing the file, let's say the string "hacked" and the hashes "53A4375C81D824C788FD1EC679B7C6B0" and "D3C659404C7959E18569848C9C9F53077A9E82E4BA2A0C69A4BFE0053C3A8274" are the IOCs (Indicators of Compromise) then we can specify the condition in the rule as follows.

```
import "hash"
rule yaraRule {
    meta:
        description = "find malicious file"
    strings:
        $string = "hacked"
    condition:
        $string or hash.md5(0, filesize) == "53A4375C81D824C788FD1EC679B7C6B0" or hash.sha256(0, filesize) == "D3C659404C7959E18569848C9C9F53077A9E82E4BA2A0C69A4BFE0053C3A8274" 
}
```

# Tools
* **YARA**: stands for "Yet Another Recursive Acronym" to search for patterns including strings and hashes, used by analysts to sweep for malicious files.
For windows download ```yara-4.3.2-2150-win64.zip``` from https://github.com/VirusTotal/yara/releases 
```
.\yara64.exe [rule] -r [dir]

# example
.\yara64.exe .\yara-rule.yara -r .\files-dir
```
![image](https://github.com/BL4CKC0FF33/WriteUps/assets/69141453/2fb2b170-d88b-4321-97da-0f8e70e855a5)


* **Loki** is IOC scanner that uses YARA rules.
For windows download ```loki_0.51.0.zip``` from https://github.com/Neo23x0/Loki/releases/tag/v0.51.0
Add the YARA .yar/.yara rule file in ```\loki*\signature-base\yara\```
```
.\loki.exe -p [dir]

# example
.\loki.exe -p .\files-dir
```
![image](https://github.com/BL4CKC0FF33/WriteUps/assets/69141453/a1798d63-1788-4966-894b-246960aed9eb)
