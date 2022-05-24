---
title: Unusual number of failed sign-in attempts
date: 2022-05-21 20:39 +0200
categories: [Hunting, MDE]
tags: [mde, hunting, true positive]
---

Today we investigate some failed logins

## The Alert
Todays alert looks simple enough, failed loggins with the user "Administrator"
But very quickly we see some not so good indicator, the login connection is from 87.251.67.65, so we will focus on this for now.
The IP seems to be hosted in Russia judging by the [whois](https://www.virustotal.com/gui/ip-address/87.251.67.65/details) entry.
Going a bit more in detail of what this IP is doing with my clients, I ran a small advanced hunting query.

```powershell
let ip = "87.251.67.65";
search in (DeviceNetworkEvents,
    DeviceFileEvents,
    DeviceLogonEvents, DeviceEvents,
    EmailEvents,
    IdentityLogonEvents,
    IdentityQueryEvents,
    IdentityDirectoryEvents,
    CloudAppEvents,
    AADSignInEventsBeta,
    AADSpnSignInEventsBeta)
Timestamp between (ago(1d) .. now())
and (// Events initiated by this IP
LocalIP == ip
or FileOriginIP == ip
or RequestSourceIP == ip
or SenderIPv4 == ip
or SenderIPv6 == ip
or IPAddress == ip
// Events affecting this IP
or RemoteIP == ip
or DestinationIPAddress == ip)
```

And this returns us some good information, the failed logins are over an RDP connection.
Now why would this even be possible?
To check a bit closer I shot off another small hunting query.

```powershell
DeviceNetworkEvents
| where DeviceId == @"mydevice"
| where RemoteIPType == @"Public"
| where ActionType == @"InboundConnectionAccepted"
| distinct LocalPort
```
This resulted in a whole plethora of public IPs that are connecting to this device over multiple ports
Ports observed:
 * 3389
 * 135
 * 8080
 * 2179
 * 2701
 * 57621
 * 139

## Flowchart
{% include mermaid_start.liquid %}
flowchart TD;
87.251.67.65 --> 3389;
3389 --> mydevice;
style mydevice stroke-dasharray: 88.5 44;
{% include mermaid_end.liquid %}


## Verdict

| Indicator                        | Thoughts                                                              | Verdict |
|----------------------------------|-----------------------------------------------------------------------|---------|
| Logins from Public IP            | Normally a public IP would not be able to just connect to an endpoint | +20%    |
| Login via RDP                    | Again, why would RDP be available from public?                        | +30%    |
| Huge amount of Public Source IPs | Looks very much like the client is reachable from public...           | +50%    |

It seems like the endpoint is reachable from the public internet.
This could have happened via UPNP, manual port forwarding, or by assigning a public IP directly to that host.
Especially the port 8080 being reachable seems like this might have been a voluntary action by the user.

**Verdict: True Positive**

## Next Steps
This endpoint should never be reachable from the public internet, what a mess
