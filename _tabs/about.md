---
title: About
icon: fas fa-info-circle
order: 4
---

## Verdict table

The Verdict table is here to make a small quick explanation of why I came to the verdict of True or False Positive.
In this example I saw one indicator which made me suspicious, and many which let me think it's more likely FP.

| Indicator                              | Thoughts                                                                                                            | Verdict |
|----------------------------------------|---------------------------------------------------------------------------------------------------------------------|---------|
| CMD started by User                    | Either compromise of host, or legitimate action by user                                                             | -10%    |
| Powershell started with odd parameters | The parameters looks pretty malicious / suspicious                                                                  | +90%    |
| Elevation of Privileges via UAC        | This is very normal behaviour and would indicate that someone has access to both user and admin passwords, unlikely | -10%    |
| Running of PsExec                      | PsExec is often used for malicious behaviour, but in this case local execution as admin makes no actual sense       | -10%    |
| Explanation by user                    | The Explanation of the user made sense and fit into my perspective of how the alert played out                      | -100%   |

**Verdict: False Positive**
