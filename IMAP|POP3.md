# Port
ports 110 and 995 are used for POP3, ports 143 and 993 are used for IMAP
# Initiate Connect
openssl s_client -connect 10.129.14.128:pop3s  
openssl s_client -connect 10.129.14.128:imaps  

# Commands
#### IMAP Commands

| **Command** | **Description** |
|---|---|
| `1 LOGIN username password` | User's login. |
| `1 LIST "" *` | Lists all directories. |
| `1 CREATE "INBOX"` | Creates a mailbox with a specified name. |
| `1 DELETE "INBOX"` | Deletes a mailbox. |
| `1 RENAME "ToRead" "Important"` | Renames a mailbox. |
| `1 LSUB "" *` | Returns the names of mailboxes the user has subscribed to. |
| `1 SELECT INBOX` | Selects a mailbox so that messages can be accessed. |
| `1 UNSELECT` | Exits the selected mailbox. |
| `1 FETCH <ID> ALL` | Retrieves data associated with a message in the mailbox. |
| `1 CLOSE` | Closes the selected mailbox and permanently removes messages marked as `\Deleted`. |
| `1 LOGOUT` | Closes the connection with the IMAP server. |

* 1 EXISTS  
* 0 RECENT  
To retrieve the complete email, including headers and body, use:  
1 fetch 1 body[]
#### POP3 Commands

| **Command** | **Description** |
|---|---|
| `USER username` | Identifies the user. |
| `PASS password` | Authenticates the user using their password. |
| `STAT` | Requests the number and total size of saved emails. |
| `LIST` | Requests the number and size of all emails. |
| `RETR id` | Retrieves the requested email by ID. |
| `DELE id` | Marks the requested email for deletion. |
| `CAPA` | Displays the server capabilities. |
| `RSET` | Resets deletion marks made during the current session. |
| `QUIT` | Closes the connection with the POP3 server. |
