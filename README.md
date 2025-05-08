Welcome!
This repo contains a simple PowerShell script to report on all things reversible encryption. 

If you didn't start there, see the companion article here:

Check-AllUsersClearText.ps1 run without adjustment will report on the Default Domain Policy, Fine-Grained Password Policies and User Account Configuration. This script will definitively detect all users in a domain that are configured with a clear-text password (reversible encryption).
Specific details for each user or configuration found, including details of how to remediate, are written to the screen.

Update 3 variables under certain conditions:

$defaultDomainPolicy -- if you renamed the policy you use to configure the default password policy

$verboseMode -- Change this to $True to globally enable verbose mode. Change in MAIN below to run verbose individually. NOTE: Changing verboseMode globally will display clear-text password information. It is recommended to run with $False first.

$DChostname -- if you are not running directly on the DC, update this to the DC you will be targeting

Reporting on clear-text password data requires the use of DSInternals. https://github.com/MichaelGrafnetter/DSInternals
_This module may be detected as malware and will need to be excluded in order to complete successfully.
I have no affiliation with DSInternals and take no responsibility for its use._

The script must be run as a Domain Administrator in a Administrative PowerShell session.

**Sample output**

Non-Verbose Mode

![image](https://github.com/user-attachments/assets/c8a78529-486a-4984-b7f0-78936342c8de)

Verbose Default Domain Policy

![image](https://github.com/user-attachments/assets/053f543b-6d45-4366-9e6e-538f998e2cc4)

Verbose FGPP

![image](https://github.com/user-attachments/assets/e40d1fe5-8d58-48ba-a7cc-aa9ad7090e97)


Verbose User Account Data

![image](https://github.com/user-attachments/assets/2b922601-0b07-4f85-b4b9-491d5b5bd5eb)

Verbose Clear-Text Data

![image](https://github.com/user-attachments/assets/86f1e441-2651-4de4-8501-867c9426de88)
