### Netcat interact with smtp server with annoymous login(line by line copy)
```
0.nc -C mail.example.org 25 //Insert a carriage return character (Ctrl+V Ctrl+M)
1.HELO example.com
2.MAIL FROM:bar@example.org
3.RCPT TO:foo@example.com
4.DATA
From: bar@example.org
To: foo@example.com
Subject: Test
Date: Thu, 20 Dec 2012 12:00:00 +0000

Testing
.
5.QUIT
```
