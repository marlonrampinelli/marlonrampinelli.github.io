---
layout: post
title: HackTheBox - Templated Walkthrough
date: 2023-09-29
categories: [Capture The Flag]
tags: [ctf, web-challenges, ssti]     # TAG names should always be lowercase
permalink: "/ctf/hackthebox-templated/"
---

## Analysis of Website

Ao iniciar o desafio vamos receber um endereço de IP, basta colar no navegador para poder acessar o desafio.

Logo de cara vemos que se trata de um framework web escrito em Python. Flask é uma estrutura WSGI leve construída em programação Python. WSGI significa **(Web Server Gateway Interface)** traduzindo para português **(Interface de Gateway de Servidor Web)**. Flask é frequentemente utilizado no back-end de aplicativos web. Jinja2 é um mecanismo de template em Python amplamente utilizado para geração dinâmica de conteúdo em aplicativos web.

![image](/assets/img/post/templated/1.png)

## Exploitation

Se o site exibir uma página de erro **(404, 403, etc.)** quando acessarmos a página que não existe, o caminho poderá estar refletido na página de erro. Por exemplo, quando tentamos acessar **/index.html** que não existe, a página de erro mostrará mensagens como a seguinte.

![image](/assets/img/post/templated/2.png)

Aqui eu usei outro exemplo, nesse caso a palavra test e novamente vemos que está sendo refletida. 

![image](/assets/img/post/templated/3.png)

Como se trata de um framework em python, concluímos que aqui ocorre uma vulnerabilidade de **Server Side Template Injection**, SSTI é uma vulnerabilidade de segurança que ocorre quando um aplicativo web permite que um invasor insira código de modelo (template) do lado do servidor em campos de entrada que são posteriormente processados e executados pelo servidor.

Vamos usar o seguinte payload:

```python
{ { 7*7 } }
```

Por exemplo, **206.189.28.151:32571/{ { 7*7 } }**. A página de erro refletirá o resultado dessa multiplicação, conforme a seguir.

![image](/assets/img/post/templated/4.png)

## Flag

Vamos usar o seguinte payload para executar comandos:

```python
 { { request.application.__globals__.__builtins__.__import__('os').popen('id').read() } }
```

![image](/assets/img/post/templated/5.png)

Executando o comando **ls**, conseguimos ver o arquivo **flag.txt**.

![image](/assets/img/post/templated/6.png)

De uma forma bem simples conseguimos a flag, esse desafio não é difícil, para quem está começando a ver sobre SSTI é bem interessante.

![image](/assets/img/post/templated/7.png)

Happy hacking, keep learning and don't forget to think outside the box!!

Fontes:

- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)

- [https://portswigger.net/web-security/server-side-template-injection](https://portswigger.net/web-security/server-side-template-injection)


