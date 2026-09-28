# Detection Lab

![tests](https://github.com/Abbe11/detection-lab/actions/workflows/tests.yml/badge.svg)

I built this while teaching myself detection engineering. It has four detections so far, and each one comes with a PowerShell detector, a Sigma rule, a sample log, and a Pester test:

1. SSH brute force, including whether the attacker got in (T1110)
2. A new account created with root privileges, a common backdoor (T1136)
3. Web attacks like SQL injection and path traversal (T1190)
4. Impossible travel, a stolen login used from another country (T1078)

The first section below walks through the brute-force detection in detail.

## The problem it solves

When someone tries to break into a server over SSH, they usually guess passwords again and again, and every failed guess gets written to the auth log. One or two failures is normal because people mistype their passwords. The hard part is telling the difference between a person fumbling their login and a machine hammering the door dozens of times.

## How it works

The detector reads the auth log and pulls out the failed logins. It groups them by the IP address they came from and counts how many times each IP failed. Any IP with 5 or more failures gets flagged. If that same IP also has a successful login, it gets marked CRITICAL, because that usually means the attack worked and someone is now inside.

I chose 5 as the threshold on purpose. It sits above what a normal user does when they mistype (2 or 3 tries) but below the volume you see in a real attack, so it catches attackers without raising an alarm over every typo.

This lines up with MITRE ATT&CK technique T1110, Brute Force.

## What is in here

- logs/sample_auth.log: a sample SSH auth log containing a brute-force attack.
- detect_bruteforce.ps1: the detector, written in PowerShell.
- detections/ssh_bruteforce.yml: the same detection as a Sigma rule, so it works in any SIEM.
- detect_bruteforce.Tests.ps1: a Pester test that proves the detector catches the known attacker.

## How to run it

```powershell
.\detect_bruteforce.ps1
Invoke-Pester .\detect_bruteforce.Tests.ps1
```

## Known false positive

A real user who mistypes their password several times in a row could get flagged. The threshold is set to make that unlikely, but it is worth knowing about.

## Detection 2: New root account (possible backdoor)

After an attacker breaks in, they often create a new user account so they can log back in later. If that account has UID 0, it has full root powers. A normal new account never gets UID 0, so one that does is a strong sign someone planted a backdoor.

This detector reads the account-creation logs and flags any new user with UID 0. It does not use a threshold like the brute-force detector, because a single root backdoor is already a full compromise, so one is too many. It maps to MITRE ATT&CK T1136, Create Account.

Files for this detection:
- logs/newuser_sample.log: sample log containing a backdoor account (name "support", UID 0).
- detect_newuser_root.ps1: the detector.
- detections/new_root_account.yml: the same rule as a Sigma rule.
- detect_newuser_root.Tests.ps1: a Pester test that proves it catches the backdoor.

Run it:

```powershell
.\detect_newuser_root.ps1
Invoke-Pester .\detect_newuser_root.Tests.ps1
```

## Detection 3: Web attacks (SQL injection and path traversal)

Web servers log every request. Normal visitors ask for pages like /about or /products. Attackers send strange requests to try to break the app, for example slipping ' OR '1'='1 into a URL to trick the database, or using ../../ to climb out of the site folder and read files like /etc/passwd.

This detector looks for those patterns in the access log and flags the IP that sent them. There's no threshold here. Nobody types a SQL injection by accident, so one request is enough for an alert.

I picked this one because it's the same kind of attack behind several flaws CISA added to its exploited list in September 2026. Sangoma Switchvox, for one, was hit through SQL injection. Maps to MITRE ATT&CK T1190, Exploit Public-Facing Application.

Files:
- logs/web_access_sample.log
- detect_webattack.ps1
- detections/web_attack.yml
- detect_webattack.Tests.ps1



## Detection 4: Impossible travel (stolen login)

This one is different from the others. The attacker's login works. There are no failed attempts and no strange requests, because they're using a real password or a stolen session cookie. In 2026 this is one of the most common ways in, through infostealer malware and fake login pages that get around MFA.

The only clue is where and when. If the same account signs in from Kenya and then from Russia 19 minutes later, one of those sign-ins isn't the real person. The detector groups sign-ins by user, puts them in time order, and compares each one with the one before it. If the country changes in under 6 hours, it raises an alert. Maps to MITRE ATT&CK T1078, Valid Accounts.

Carol in the sample log is there on purpose. She signs in from Kenya and then from the UK 16 hours later. A direct flight is around 9 hours, so that's possible, and the detector leaves her alone. One of the tests checks exactly that.

Known weaknesses:
- It uses a flat 6 hour rule instead of real distances, so a quick hop to a neighbouring country (Kenya to Uganda, say) would still get flagged.
- VPNs make people look like they're somewhere else. In real SOCs this is one of the most common false positives for this kind of alert.

Files:
- logs/signin_sample.csv
- detect_impossible_travel.ps1
- detections/impossible_travel.yml
- detect_impossible_travel.Tests.ps1

