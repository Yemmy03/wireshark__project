# Wireshark Analysis Report

# Network Traffic Analysis using Wireshark

## Overview

This project report was focused on utilizing Wireshark to analyze network traffic captured in select PCAP (Packet Capture) files. The goal was to identify network anomalies, investigate security issues, and extract critical information from captured packets. 

P.S. The data for this analysis was obtained from [Malware Traffic Analysis Net,](https://www.malware-traffic-analysis.net/training-exercises.html) specifically referencing the PCAP capture dated 2015-02-08. This dataset is publicly available and commonly used in network forensics training and malware investigation exercises. 

Please see the image below for the scenario provided by Malware Traffic Analysis Net:

<img width="1719" height="207" alt="image (14)" src="https://github.com/user-attachments/assets/2717bdcf-7b50-4b87-aa40-b62443a05454" />


## Primary Objectives
```
- Understand and apply Wireshark filters to extract useful data from network traffic
- Identify potential security issues, including exposed credentials and improper protocols
```
## Step-by-Step Breakdown of Scenario Interpretation
```
- Spotted the Incident Trigger
Mike reported that his computer was "acting weird," raising a red flag. Despite the vague description, the timing of the issue and Mike’s reluctance to explain further hinted at potential malicious activity.
- Help Desk Escalation
The Security Operations Center (SOC) became involved after the Help Desk escalated the issue. This framed the project as a network forensic task, placing me in the analyst’s shoes.
- Reviewed the PCAP Timeline
Since the scenario already established that the network capture was taken shortly before Mike’s complaint, I narrowed my investigation to focus on pre-incident traffic.
- Searched for Unusual Connections
I filtered for high-connection activity in a short timeframe to identify any abnormal spikes in communication; a usual indicator of  data exfiltration.
- Inspected Potential C2 (Command and Control) or Upload Behaviour
By checking for “POST requests and payloads,” I tried to determine whether data was being sent from Mike’s machine to an unknown server, typical of a compromised host.
- Looked for Authentication or Credentials
Expecting that Mike may have unknowingly submitted credentials or sensitive data, I examined payloads for fields like “username” or “password”, although none were present.
- Verified Absence of Authorization Headers
This helped rule out certain types of HTTP authentication attacks, narrowing down the threat model.
- Mapped Findings to Storyline
Each task was built to trace what Mike couldn’t explain: by correlating timeline, payloads, request types, and destination hosts, I established a narrative of what the computer was doing “weirdly.”
```
## Project Breakdown and Analysis

### Task 1: Identifying High-Volume Connections

The first task involved examining the PCAP file to identify which IP addresses were making a large number of connections within a short timeframe. To achieve this, a combination of Wireshark filters was used to detect high-frequency connections.

- How I Did It:
    - I loaded the packet capture file into Wireshark.
    
    <img width="1911" height="608" alt="image (15)" src="https://github.com/user-attachments/assets/520a16ac-c730-49b6-b961-3105b8c99f99" />


    - Then, I applied the ‘ip.addr and tcp.stream’ filter to isolate the protocol of interest.
    
    <img width="1913" height="40" alt="image (16)" src="https://github.com/user-attachments/assets/13096068-6fa6-450e-86c6-818a603932cd" />

    
    - Thereafter, I performed statistical analysis using the "Statistics" menu in Wireshark, focusing on the "Endpoints" and "Conversations" sections.
    - By filtering and sorting the data, I identified connections with high frequency over a short period, which revealed potential patterns of abnormal network activity or possible distributed denial-of-service (DDoS) attempts.
    
    <img width="1903" height="578" alt="image (17)" src="https://github.com/user-attachments/assets/07527341-1de5-40f2-a360-04188bef5dfa" />

    
- Outcome:
    - The connections made by several IP addresses were identified, along with the protocols they used. I discovered that the suspicious IP addresses are the ones with extreme number of packets compared to others (see image for addresses: External address ‘62.210.114.67’ and Internal address ‘192.168.137.83’)
    - This task helped me understand basic Wireshark statistics and provided insight into how to monitor network activity for unusual spikes.

### Task 2: Inspecting HTTP Traffic for Credentials

In the second task, the goal was to locate usernames and passwords transmitted in the captured traffic, specifically within HTTP packets. The logic here is to filter the traffic to isolate HTTP requests and identify any form submissions or authentication headers.

- How I Did It:
    - To narrow the focus to HTTP POST requests, I applied the filter ‘http.request.method == "POST".
    
    <img width="1919" height="35" alt="image (18)" src="https://github.com/user-attachments/assets/e6b80c94-34b6-4c23-8fe2-5c2c26db2bcb" />

    
    - Then, I carefully examined the captured HTTP traffic, paying particular attention to patterns of credential submission, such as form fields labeled with "username" and "password.”
    
    <img width="1915" height="112" alt="image (23)" src="https://github.com/user-attachments/assets/9085744f-4aa1-4f1c-aa23-d4ddfb2ec861" />

    
- Outcome:
    - Despite my efforts, no visible username/password pairs were found in POST requests. This outcome suggests that the credentials may have been transmitted using encrypted or non-plaintext methods.
    - This task showed the importance of proper filtering and the variety of ways sensitive information can be handled in network traffic, including base64 encoding, token-based authentication, or encryption.

### Task 3: Decoding Base64 Encoded Credentials

Task 3 involved searching for Base64 encoded credentials that could potentially appear in HTTP authorization headers or other parts of the traffic. This task was designed to test the ability to decode encoded data to retrieve sensitive information.

- How I Did It:
    - I applied the filter ‘http.authorization’ to search for any Base64-encoded credentials within the traffic.
    
    <img width="1915" height="38" alt="image (22)" src="https://github.com/user-attachments/assets/ebaaa7a2-104d-4440-bd03-34f84c464e7c" />


    - The presence of Base64 strings would suggest that the credentials were sent using Basic Authentication.
- Outcome: No Base64 encoded credentials were found in the traffic. This suggests the possibility that the captured traffic either did not use Basic Authentication or that the credentials were encrypted or masked in other ways.

### Task 4: Locating Exposed User Credentials

The final task involved identifying and extracting any usernames and passwords that might have been exposed in the traffic, regardless of the transmission method used. This task was meant to expose any suspicious credentials within the traffic and assessing their security implications.

- How I Did It:
    - I applied the filter ‘http.request.method == "POST" to pinpoint any form submissions that might carry user credentials.
    
    <img width="1917" height="44" alt="image (21)" src="https://github.com/user-attachments/assets/10bd06a8-24ec-4c7d-a07f-b41cf05301a1" />

    
    - In addition to filtering, I also followed individual TCP streams to manually inspect potential login attempts embedded within the payloads.
    - Furthermore, I examined headers and request details for cookies, tokens, or any other indicators that could be linked to user authentication mechanisms.
- Outcome: Although there was a suspicious IP address in the traffic, however, no exposed credentials were found in the traffic, either in form of data or other HTTP headers. 
This only suggests two things; 
I) The traffic captured was either encrypted by more secure methods of authentication (e.g., token-based systems or HTTPS encryption) or 
II) This whole incident could have just been a false positive.

## Conclusion
```
This project provided me with hands-on experience in network traffic analysis, broadening my understanding of data security and packet inspection. Through this project, I successfully demonstrated the importance of robust security measures in protecting data integrity and privacy.
```
