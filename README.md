# Detection Lab: SSH Brute-Force Detection

This is a small project I built while learning detection engineering. It reads Linux SSH logs, picks out brute-force login attacks, and tells you when one of those attacks actually succeeded.

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
