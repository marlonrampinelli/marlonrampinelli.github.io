---
layout: post
title: WordPress Hacking
date: 2023-09-21
categories: [Offensive Security]
tags: [wordpress]     # TAG names should always be lowercase
image: /assets/img/post/wordpress-hacking/wordpress.png
permalink: "/offsec/wordpress-hacking/"
---

## Introdução

O WordPress é o Sistema de Gerenciamento de Conteúdo (CMS) de código aberto mais popular, alimentando quase um terço de todos os sites do mundo. Ele pode ser usado para várias finalidades, como hospedagem de blogs, fóruns, comércio eletrônico, gerenciamento de projetos, gerenciamento de documentos e muito mais. O WordPress é altamente personalizável, ele tem uma grande biblioteca de extensões chamadas temas e plugins, tanto gratuitos quanto pagos, que podem ser adicionados para aprimorar o site. No entanto, sua capacidade de personalização e natureza extensível o tornam propenso a vulnerabilidades por meio de temas e plugins de terceiros. O WordPress é escrito em PHP e geralmente é executado no Apache com o MySQL como back-end. Muitas empresas de hospedagem oferecem o WordPress como uma opção ao criar um novo site e até mesmo ajudam com tarefas de backend, como atualizações de segurança.

## O que é um CMS?

Um CMS é uma ferramenta avançada que ajuda a criar um site sem a necessidade de codificar tudo do zero (ou mesmo de saber escrever código). O CMS faz a maior parte do "trabalho pesado" no lado da infraestrutura para que você se concentre mais nos aspectos de design e apresentação do site do que na estrutura de back-end.

Um CMS é formado por dois componentes principais:

- Um aplicativo de gerenciamento de conteúdo (CMA) - a interface usada para adicionar e gerenciar conteúdo.
- Um aplicativo de distribuição de conteúdo (Content Delivery Application, CDA) - o back-end que recebe as informações inseridas no CMA e reúne o código em um site funcional e visualmente atraente.

## Estrutura do WordPress

O WordPress pode ser instalado em um host Windows, Linux ou Mac OSX. Todos os arquivos e diretórios de suporte do WordPress poderão ser acessados na raiz da web localizada em /var/www/html. Abaixo está a estrutura de diretórios de uma instalação padrão do WordPress, mostrando os principais arquivos e subdiretórios necessários para que o site funcione corretamente.

```bash
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

## Principais arquivos do WordPress

O diretório raiz do WordPress contém arquivos que são necessários para configurar o WordPress para funcionar corretamente.

- **index.php** é a página inicial do WordPress.
- **license.txt** contém informações úteis, como a versão do WordPress instalada.
- O arquivo **wp-activate.php** é usado para o processo de ativação de e-mail ao configurar um novo site do WordPress.
- A pasta **wp-admin** contém a página de login para acesso de administrador e o painel de controle de back-end. Depois que um usuário faz login, ele pode fazer alterações no site com base nas permissões que lhe foram atribuídas. A página de login pode estar localizada em um dos seguintes caminhos:

```bash
/wp-admin/login.php
/wp-admin/wp-login.php
/login.php
/wp-login.php
```
Esse arquivo também pode ser renomeado para dificultar a localização da página de login.

- **xmlrpc.php** é um arquivo que representa um recurso do WordPress que permite que os dados sejam transmitidos com HTTP atuando como mecanismo de transporte e XML como mecanismo de codificação. Esse tipo de comunicação foi substituído pela REST API do WordPress, https://developer.wordpress.org/rest-api/reference

## Arquivo de configuração do WordPress

O arquivo **wp-config.php** contém as informações exigidas pelo WordPress para se conectar ao banco de dados, como o nome do banco de dados, o host do banco de dados, o nome de usuário e a senha, keys e salts de autenticação e o prefixo da tabela do banco de dados. Esse arquivo de configuração também pode ser usado para ativar o modo DEBUG, que pode ser útil na solução de problemas.

## Principais diretórios do WordPress

A pasta wp-content é o diretório principal onde os plugins e os temas são armazenados. O subdiretório uploads/ geralmente é onde são armazenados todos os arquivos carregados na plataforma. Esses diretórios e arquivos devem ser enumerados com cuidado, pois podem conter dados confidenciais que podem levar à execução remota de código ou à exploração de outras vulnerabilidades ou configurações incorretas.

### wp-content

```bash
├── index.php
├── plugins
└── themes
```

O diretório wp-includes contém tudo, exceto os componentes administrativos e os temas que pertencem ao site. Esse é o diretório em que os arquivos principais são armazenados, como certificados, fontes, arquivos JavaScript e widgets.

### wp-includes

```bash
├── theme.php
├── update.php
├── user.php
├── vars.php
├── version.php
├── widgets
├── widgets.php
├── wlwmanifest.xml
├── wp-db.php
└── wp-diff.php
```

## Enumeração WordPress

É sempre importante saber com que tipo de aplicativo estamos trabalhando. Uma parte essencial da fase de enumeração é descobrir o número da versão do software. Isso é útil na busca de configurações incorretas comuns, como senhas padrão que podem ser definidas para determinadas versões de um aplicativo, e na busca de vulnerabilidades conhecidas para um determinado número de versão. Podemos usar uma variedade de métodos para descobrir o número da versão manualmente. A primeira e mais fácil etapa é revisar o código-fonte da página e podemos procurar a tag meta generator, ou simplesmente usar um terminal para fazer esse processo.

**código-fonte:**

```bash
<link rel='https://api.w.org/' href='http://blog.site.com/index.php/wp-json/' />
<link rel="EditURI" type="application/rsd+xml" title="RSD" href="http://blog.site.com/xmlrpc.php?rsd" />
<link rel="wlwmanifest" type="application/wlwmanifest+xml" href="http://blog.site.com/wp-includes/wlwmanifest.xml" /> 
<meta name="generator" content="WordPress 6.2.2" />
```

**Usando curl:**

```bash
curl -s -X GET http://blog.site.com/ | grep '<meta name="generator"'

<meta name="generator" content="WordPress 6.2.2" />
```

## Enumeração de plugins e themes

Também podemos encontrar informações sobre os plugins instalados analisando o código-fonte manualmente, inspecionando o código-fonte da página ou filtrando as informações usando o curl.

**Enumerando plugins:**

```bash
curl -s -X GET http://blog.site.com/ | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'wp-content/plugins/*' | cut -d"'" -f2
```

**Enumerando temas:**

```bash
curl -s -X GET http://blog.site.com/ | sed 's/href=/\n/g' | sed 's/src=/\n/g' | grep 'themes' | cut -d"'" -f2
```

## Enumeração de usuários

A enumeração de uma lista de usuários válidos é uma fase crítica de uma avaliação de segurança do WordPress. Podemos adivinhar as credenciais padrão ou realizar um ataque de força bruta à senha. Se formos bem-sucedidos, poderemos fazer login no backend do WordPress como um autor ou até mesmo como um administrador. Esse acesso pode ser potencialmente aproveitado para modificar o site do WordPress ou até mesmo interagir com o servidor da Web subjacente.

Um método bem interessante é acessar o seguinte diretório **/wp-json/wp/v2/users**, ele nos permite obter uma lista de usuários.

```bash
$ curl http://blog.site.com/wp-json/wp/v2/users | jq

[
  {
    "id": 1,
    "name": "admin",
    "url": "",
    "description": "",
    "link": "http://blog.site.com/index.php/author/admin/",
  },
  {
    "id": 2,
    "name": "castiel",
    "url": "",
    "description": "",
    "link": "http://blog.site.com/index.php/author/castiel/",
  },
```

# Automatizando o processo com WPScan

O **WPScan** é uma ferramenta automatizada de verificação e enumeração do WordPress. Ela determina se os vários temas e plugins usados por um site WordPress estão desatualizados ou vulneráveis. Ele é instalado por padrão no Parrot OS e Kali Linux.

Há várias opções de enumeração que podem ser especificadas, como plugins vulneráveis, todos os plugins, enumeração de usuários e muito mais. É importante entender todas as opções disponíveis e ajustar o scanner de acordo com o nosso objetivo, não simplesmente rodar a ferramenta por rodar.

A flag **--enumerate** é usado para enumerar vários componentes do aplicativo WordPress, como plugins, temas e usuários. Por padrão, o WPScan enumera plugins, temas, usuários, mídia e backups vulneráveis. No entanto, argumentos específicos podem ser fornecidos para restringir a enumeração a componentes específicos. Por exemplo, todos os plugins podem ser enumerados usando os argumentos **--enumerate ap**, ou podemos usar **--enumerate u**, para enumerar usuários.

Exemplo:

```bash
wpscan --url http://blog.site.com/ --enumerate ap 
wpscan --url http://blog.site.com/ --enumerate u
```

# Best Practices

Abaixo estão algumas práticas recomendadas para evitar ataques a um site WordPress.

## Realize atualizações regulares

Esse é um princípio fundamental para qualquer aplicativo ou sistema e pode reduzir muito o risco de um ataque bem-sucedido. Certifique-se de que o núcleo do WordPress, bem como todos os plugins e temas instalados, sejam mantidos atualizados. O console de administração do WordPress geralmente nos avisa quando os plugins ou temas precisam ser atualizados ou quando o próprio WordPress precisa de uma atualização.

## Gerenciamento de plugins e temas

Instale somente temas e plugins confiáveis do site [WordPress](https://wordpress.org/). Antes de instalar um plugin ou tema, verifique suas avaliações, popularidade, número de instalações e data da última atualização. Se um deles não for atualizado há anos, isso pode ser um sinal de que não é mais mantido e pode apresentar vulnerabilidades não corrigidas. Faça uma auditoria de rotina em seu site WordPress e remova todos os temas e plugins não utilizados. Isso ajudará a garantir que nenhum plugin desatualizado seja esquecido e potencialmente vulnerável.

## Gerenciamento de usuários

Os usuários são frequentemente visados, pois geralmente são vistos como o elo mais fraco de uma organização. As práticas recomendadas relacionadas ao usuário a seguir ajudarão a melhorar a segurança geral de um site WordPress.

- Desative o usuário padrão admin e crie contas com nomes de usuário difíceis de adivinhar
- Imponha senhas fortes
- Ative e aplique a autenticação de dois fatores (2FA) para todos os usuários
- Restrinja o acesso dos usuários com base no conceito de privilégio mínimo
- Audite periodicamente os direitos e o acesso dos usuários. Remova todas as contas não utilizadas ou revogue o acesso que não for mais necessário

## Gerenciamento de configuração

Certas alterações de configuração podem aumentar a postura geral de segurança de uma instalação do WordPress.

- Instale um plugin que não permita a enumeração de usuários para que um invasor não consiga reunir nomes de usuários válidos para serem usados em um ataque de pulverização de senha
- Limite as tentativas de login para evitar ataques de força bruta de senha
- Renomeie a página de login wp-admin.php ou reposicione-a para que não seja acessível à Internet ou seja acessível somente por determinados endereços IP

![image](/assets/img/post/wordpress-hacking/hackerman.jpg)

Não se esqueça de pensar fora da caixa.

Happy hacking and keep learning!!
