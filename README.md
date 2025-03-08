# Meta-Blue
An open source hunt framework for Microsoft Windows networks. Find out your network's host configuration baseline and what lies outside of it on the fly. 

Currently collects 76 forensically relevant data points.


# In Progress:

The repo is currently in a weird state. Originally, the intent of the project was to have a single .ps1 to do everything. We are working to move the remote collection into its own module so that the local collect is a much 
lighter weight script.

## Collection
 - A few of the datapoints being collected are either irrelevant or do not return something of implict value.
 - Reworking services to scrape registry instead of get-services/gwmi win32_service/etc.
 - Incorporating checks from tools like [WinPwn](https://github.com/S3cur3Th1sSh1t/WinPwn) and [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS). (if attackers know where they can privesc, shouldn't you?)

## UI/UX
 - Finally working on getting rid of the menu.
 - Using cmdletbinding in next version
