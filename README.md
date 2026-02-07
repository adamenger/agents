# Hello, Agents! 

This repo is a collection of experimental agents. These agents run entirely
locally using your local gpu and attempt to explore the usefulness of LLM
agents running on your machine and assisting with certain tasks. 

## Agents 

### Pihole Threat Intel agent 

This is a proof of concept agent which evaluates historical DNS data collected
by Pi-Hole to determine if any of the requested domains look suspicious or
malicious. This stack has two modes "Simple" and "SIEM". The simple stack is
meant as a proof of concept to explore LLM reasoning about DNS data. The SIEM
stack is designed to show SOC and threat hunting analysts what incorporating an
LLM in the alert workflow could look like.
