# Email Gateway Security Lab

## Overview

This lab is a security-focused email gateway I built on Ubuntu. The idea is simple. Instead of letting emails go straight to the user, they first go through a security pipeline that checks if they are spam or malware, verifies the email is actually coming from who it says it is, and blocks anything suspicious. Everything gets logged and sent to Splunk so I can monitor and alert on suspicious activity.

I built this to practice SOC skills and understand how email-based attacks like phishing are detected and blocked in real environments.

## Tools Used

| Tool | Role |
|------|------|
| Postfix | Receives incoming emails and routes them through the security pipeline |
| Amavis | Works as the middleman. It takes the email from Postfix and sends it to SpamAssassin and ClamAV for analysis |
| SpamAssassin | Checks the email content and gives it a spam score. Anything above 5.0 gets flagged |
| ClamAV | Scans for malware and viruses in the email and attachments |
| OpenDKIM | Signs outgoing emails with a digital signature and verifies incoming ones. Connected to Postfix as a milter on port 12301 |
| OpenDMARC | Evaluates DMARC policy using SPF/DKIM results and domain alignment. Based on the policy, suspicious emails can be monitored, quarantined, or rejected. Connected to Postfix as a milter on port 54321 |
| Bind9 | Local DNS server used to publish the SPF, DKIM, and DMARC records for homelab.local |
| Dovecot | IMAP server that stores emails and makes them accessible on ports 143 and 993 |
| Postgrey | Greylisting. Temporarily rejects emails from unknown senders. Legitimate servers retry, spammers usually do not |
| Fail2ban | Monitors logs and bans IPs that have too many failed attempts against Postfix, Dovecot, or SSH |
| Splunk | Collects all the mail logs, shows detections in a dashboard, and triggers alerts on blocked events |

## How the Email Flow Works

1. An email comes in and Postfix receives it on port 25
2. TLS negotiation happens. If the sending server supports it, the connection gets encrypted
3. Postfix checks the sender IP against RBLs. If the IP is a known spam source, the email gets rejected right there
4. Postfix checks Postgrey. If the sender is unknown, the email gets temporarily rejected. Legitimate servers will retry
5. OpenDKIM verifies the DKIM signature of the email
6. OpenDMARC checks the DMARC policy of the sender's domain
7. Postfix sends the email to Amavis on port 10024
8. Amavis passes it through SpamAssassin and ClamAV for analysis
9. SpamAssassin scores the email based on its content and headers
10. ClamAV scans for known malware signatures
11. If either one flags it, Amavis blocks the email and puts it in quarantine
12. If the email is clean, Amavis returns it to Postfix on port 10025
13. Postfix delivers it to the mailbox
14. Dovecot makes it accessible via IMAP
15. The result gets logged to /var/log/mail.log and Splunk picks it up in real time

## Email Authentication

One of the things I focused on was setting up proper email authentication. This is what companies use to stop attackers from sending emails pretending to be someone else.

**SPF** checks if the server sending the email is actually authorized to send on behalf of that domain. I configured this as a DNS TXT record in Bind9:
```
v=spf1 ip4:127.0.0.1 a mx ~all
```

**DKIM** adds a digital signature to every outgoing email. The private key lives on the server and signs the email. The public key is published in DNS so anyone receiving the email can verify it was not tampered with and actually came from the right place. I generated the keys with opendkim-genkey and published the public key in Bind9.

**DMARC** is the policy that decides what to do when an email fails authentication checks and alignment. I set it to quarantine, which means emails that fail DMARC evaluation can be sent to spam or quarantine. I also configured it to send reports to the admin mailbox. The record looks like this:
```
v=DMARC1; p=quarantine; rua=mailto:admin@homelab.local; pct=100
```

## Security Hardening

On top of the spam and malware filtering, I added a few more layers to make the gateway more realistic and harder to abuse.

**TLS** encrypts the connection between mail servers so emails cannot be read in transit. I generated a self-signed certificate with OpenSSL and configured Postfix to offer TLS on every incoming connection.

**RBLs** are real-time blacklists of IPs known for sending spam. I configured Postfix to check three of them: Spamhaus, SpamCop, and Barracuda. If a sender IP is on any of those lists, the email gets rejected before it even reaches SpamAssassin.

**Postgrey** adds greylisting. The first time an unknown sender tries to deliver an email, the server temporarily rejects it with a "try again later" message. Real mail servers are designed to retry. Most spam scripts are not.

**Fail2ban** watches the logs and automatically bans IPs that are trying to brute force the server. I set it up to monitor Postfix, Dovecot, and SSH with different thresholds for each.

## Detection Testing

### Spam Test (GTUBE)
The GTUBE string is the industry standard for testing spam detection, similar to how EICAR is used for antivirus. Any properly configured SpamAssassin must detect it.

I sent a test email through SMTP containing the GTUBE string and SpamAssassin flagged it with a score of 999.1. Amavis blocked it and quarantined it.

### Automated Test Script
Instead of typing all the SMTP commands manually every time, I wrote a Bash script to automate the spam test:
```bash
#!/bin/bash
(
echo "EHLO test.local"
sleep 1
echo "MAIL FROM:<attacker@evil.com>"
sleep 1
echo "RCPT TO:<socadmin@localhost>"
sleep 1
echo "DATA"
sleep 1
echo "Subject: Spam Test"
echo "From: attacker@evil.com"
echo "To: socadmin@localhost"
echo ""
echo "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
echo "."
sleep 1
echo "QUIT"
) | telnet localhost 25
```

## Splunk Integration

I configured Splunk to monitor /var/log/mail.log in real time. As emails get processed, the logs flow into Splunk automatically.

### Dashboard
I built a dashboard called Email Gateway Security with two panels:

![Email Gateway Dashboard](splunk-dashboard-email-gateway.png)

- **Spam Actions - Blocked vs Passed** - pie chart showing how many emails were blocked vs delivered
- **Blocked Spam Details** - table showing the sender, recipient, and spam score for every blocked email

### Alert
I set up a real-time alert that triggers whenever a Blocked event is detected. Severity is set to High.

### SPL Queries

Blocked spam with details:
```
index=* sourcetype=mail_log amavis Blocked
| rex "<(?<sender>[^>]+)> ->"
| rex "-> <(?<recipient>[^>]+)>"
| rex "Hits: (?<score>[\d.]+)"
| table _time sender recipient score
```

Blocked vs Passed summary:
```
index=* sourcetype=mail_log amavis
| eval action=if(match(_raw,"Blocked"),"Blocked","Passed")
| stats count by action
```

![Blocked Spam Search](splunk-search-blocked-spam.png)

## MITRE ATT&CK Mapping

| Technique | ID | How It's Detected |
|-----------|-----|-------------------|
| Phishing | T1566 | SpamAssassin scores the email content, Amavis blocks and quarantines it, Splunk triggers an alert on blocked events |

## Environment

- OS: Ubuntu 22.04 LTS
- SIEM: Splunk Enterprise 10.2
- VM: VMware Workstation

## Key Takeaways

- Email is one of the biggest attack vectors out there, so having something that checks emails before they reach the user is really important.
- Amavis is what makes everything work together. It sits in the middle and coordinates SpamAssassin and ClamAV so Postfix does not have to deal with each one separately.
- Connecting the logs to Splunk showed me how important visibility is. Without it, you would not even know an email got blocked.
- Writing the Bash script to automate the spam tests made me realize how useful scripting is for security tasks. Instead of typing the same commands over and over, one script does it in seconds.
- This lab helped me understand how phishing detection works at the network and infrastructure level, not just on the endpoint.
- Setting up SPF, DKIM, and DMARC showed me how companies protect their domains from being impersonated. It is not just about filtering bad emails, it is also about making sure your own emails are trusted.
- Adding TLS, RBLs, Fail2ban, and Postgrey made me realize that email security is not just one tool. It is multiple layers working together, and removing any one of them would make the whole thing weaker.
