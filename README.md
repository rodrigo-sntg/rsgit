# RSGIT Project

Estudo de git reproduzindo suas principais operações com python.

Ideia iniciada com: https://wyag.thb.lt/ e https://benhoyt.com/writings/pygit/;

Atualmente o projeto conta apenas com as funções:
```
rsgit init // inicia o repo git
rsgit add arquivo // adiciona um arquivo ao index
rsgit commit -m "mensagem" -a "autor" // commita que estão no index
rsgit cat-file commit 0000 // exibe as informações do commit, passar os 4 primeiros digitos do sha-1 gerado no commit
rsgit status // exibe como está a worktree
rsgit diff // exibe as alterações desde o ultimo commit
rsgit push -p senha -u usuario https://github.com/usuario/repositorio.git // faz o commit para o repositório

```