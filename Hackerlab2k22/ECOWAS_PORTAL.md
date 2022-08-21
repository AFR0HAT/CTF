
voir le type de fichier avec la commande `file` , 

![[file_result.png]]
c'est un fichier binaire.


- on fait un `strings` pour voir si on peut trouver quelque chose mais  rien.
```bash
└─$ strings ecowas_portal      
/lib64/ld-linux-x86-64.so.2
mgUa
puts
stdin
printf
fgets
strlen
__cxa_finalize
__libc_start_main
libc.so.6
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
u+UH
[]A\A]A^A_
ECOWAS ADMIN PORTAL : 
Flag wrong. Try again.
Check failed
Success!
;*3$
GCC: (Debian 11.3.0-5) 11.3.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
chal.c
__FRAME_END__
__init_array_end
_DYNAMIC
__init_array_start
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_csu_fini
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
strlen@GLIBC_2.2.5
printf@GLIBC_2.2.5
encrypt
__libc_start_main@GLIBC_2.2.5
fgets@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
__libc_csu_init
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

- On le désassemble sur https://dogbolt.org avec  Hex-Rays
la fonction main  et encrypt :
``` C
//----- (0000000000001169) ----------------------------------------------------
__int64 __fastcall encrypt(int a1, int a2)
{
  return a2 ^ (unsigned int)(a1 - 20);
}


//----- (000000000000117E) ----------------------------------------------------
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  size_t v5; // rbx
  int v6[28]; // [rsp+0h] [rbp-120h]
  char s[142]; // [rsp+70h] [rbp-B0h] BYREF
  char v8; // [rsp+FEh] [rbp-22h]
  char v9; // [rsp+FFh] [rbp-21h]
  __int64 v10; // [rsp+100h] [rbp-20h]
  int i; // [rsp+10Ch] [rbp-14h]

  puts("ECOWAS ADMIN PORTAL : ");
  v6[0] = 47;
  v6[1] = 65;
  v6[2] = 48;
  v6[3] = 72;
  v6[4] = 74;
  v6[5] = 37;
  v6[6] = 39;
  v6[7] = 26;
  v6[8] = 39;
  v6[9] = 87;
  v6[10] = 21;
  v6[11] = 73;
  v6[12] = 16;
  v6[13] = 45;
  v6[14] = 17;
  v6[15] = 43;
  v6[16] = 12;
  v6[17] = 14;
  v6[18] = 12;
  v6[19] = 55;
  v6[20] = 11;
  v6[21] = 11;
  v6[22] = 10;
  v6[23] = 10;
  v6[24] = 6;
  v10 = 25LL;
  fgets(s, 128, _bss_start);
  v3 = strlen(s);
  if ( v10 == v3 - 1 )
  {
    for ( i = 0; ; ++i )
    {
      v5 = i;
      if ( v5 >= strlen(s) - 1 )
        break;
      v9 = v6[i];
      v8 = encrypt(s[i], i);
      if ( v8 != v9 )
      {
        printf("Check failed");
        return 1;
      }
    }
    puts("Success!");
    return 0;
  }
  else
  {
    printf("Flag wrong. Try again.");
    return 1;
  }
} ```

on trouve un tableau (`v6`) de **25 caractères** (Sound interesting )
renommer les variables: 
 `v6` : `chars_flag`, `v10`: `flag_length`, `s`; `input`.
 
 j'ai converti ce code en python:
 ``` python
import string 

s = string.ascii_letters + string.punctuation + string.digits 
 
def encrypt(a,b): 
	 return b ^ (a-20) 
	 
v6 = [47, 65, 48, 72, 74, 37, 39, 26, 39, 87, 21, 73, 16, 45, 17, 43, 12, 14, 12, 55, 11, 11, 10, 10,6] 

flag = "" 
for i in range(len(v6)): 
	for j in range(len(s)): 
		v9 = v6[i] 
		v8 = encrypt(ord(s[j]), i)  
		if v9 == v8 : 
			flag+=s[j]

print(flag)
```

THAT'S IT !!!!! 
