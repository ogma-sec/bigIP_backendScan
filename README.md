## What is bigIP_backendScan ?

bigIP_backendScan is a tool that can be used to scan internal IP:Port used in a F5 BigIP load-balancing pool.

It exploit a weakness in the default configuration of F5 BigIP land-balancer that make BigIP write in a encoded way IP:port of the server on which a session is assigned inside a lad-balancer pool. This information can be decoded by the client to know which port and internal IP are used.

This article expose more details about this subject : https://ogma-sec.fr/bigip_backendscan-cookies-bigip-et-fuite-dinformation/

##How to use it

To use the default parameters that makes 50 requests to a web target to get all servers inside a cluster, just use bigIP_backendScan as follow : 
```
bigIP_backendScan.py -u https://mytarget.tld
```
To make more request (e.g. 100 instead of 50), use the "-r" parameter" : 
```
bigIP_backendScan.py -u http://mytarget.tld:8080 -r 100
```
To check on a non-default named cookie, that normally contains "BigIP_", use the "-n" parameter :
```
bigIP_backendScan.py -u https://mytarget.tld:443 -n customBigIPCookieName
```
