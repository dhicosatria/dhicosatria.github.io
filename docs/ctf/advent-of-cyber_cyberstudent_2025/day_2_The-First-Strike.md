# day 2 The First Strike

category : Forensics

## **Description**

A series of repeated authentication failures was detected against the **FTP** service. The traffic pattern matched known Krampus Syndicate infrastructure, indicating the beginning of their intrusion attempts. After a sustained burst of password guessing, one request finally succeeded.

Your task is to examine the logs or packet capture, identify which account was **compromised**, and determine the password used during the successful login.

Submit your answer as: **`csd{username_password}`**

---

*Reminder: Answers are **case sensitive***

## **Attachments**

[**ftpchal.pcap**](https://files.vipin.xyz/api/public/dl/jBiEAP2X/Day%202/ftpchal.pcap)

Open the provided pcap, theres many ftp connections. Grep  `PASV`  to find a valid login:

![image.png](media/day2.png)


hint :

- Our Dark Web Elves suggest starting with packet inspection. A tool like Wireshark can help you review the pcap.
- Focus on the details. Filtering the Info column may reveal the moment the Syndicate got in.
****