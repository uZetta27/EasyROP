# EasyROP
Esta herramienta en Python permite buscar gadgets, operaciones formadas por gadgets; y generar ROP chains en binarios Portable Executable (PE). EasyROP se basa en el desensamblador Capstone para la búsqueda de gadgets.

### Instalación
EasyROP necesita la instalación de [Capstone](http://www.capstone-engine.org/download.html) y [pefile](https://pypi.python.org/pypi/pefile/).

Una vez resueltas sus dependencias, EasyROP se puede utilizar mediante:
```
$ python EasyROP.py
```

### Uso
```
usage: EasyROP.py [-h] [-v] [--binary <path>] [--depth <bytes>] [--all]
                  [--op <op>] [--reg-src <reg>] [--reg-dst <reg>] [--ropchain]
                  [--nojop] [--noretf] [--test-os] [--test-binary <path>]
                  [--ropattack <path>]

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         Display EasyROP's version
  --binary <path>       Specify a binary path to analyze
  --depth <bytes>       Depth for search engine (default 5 bytes)
  --all                 Disables the removal of duplicate gadgets
  --op <op>             Search for operation: lc, move, load, store, add, sub,
                        and, or, xor, not, cond1, cond2, nop, neg, adc, clc
  --reg-src <reg>       Specify a source reg to operation
  --reg-dst <reg>       Specify a destination reg to operation
  --ropchain            Enables ropchain generation to search for operation
  --nojop               Disables JOP gadgets
  --noretf              Disables gadgets terminated in a far return (retf)
  --test-os             Analyze KnownDLLs of the computer to test viability of
                        an attack (it takes long time)
  --test-binary <path>  Analyze a binary to test viability of an attack
  --ropattack <path>    Generate ROP attack from file
```

### Operaciones
Las operaciones son operaciones de alto nivel creadas mediante conjuntos de gadgets. Un ejemplo de dos conjuntos para realizar la operación de mover un valor de un registro a otro sería:
```
xchg dst, src
```
```
xor dst, dst
add dst, src
```

### Especificación de operaciones
Siguiendo la estructura del siguiente DTD se puede realizar la especifiación de operaciones propias mediante XML:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE operations [
        <!ELEMENT operations (operation)+>
        <!ELEMENT operation (set)+>
        <!ATTLIST operation
                name CDATA #REQUIRED>
        <!ELEMENT set (ins)+>
        <!ELEMENT ins (reg1|reg2)*>
        <!ATTLIST ins
                mnemonic CDATA #REQUIRED>
        <!ELEMENT reg1 (#PCDATA)>
        <!ATTLIST reg1
                value CDATA #IMPLIED>
        <!ELEMENT reg2 (#PCDATA)>
        <!ATTLIST reg2
                value CDATA #IMPLIED>
        ]>
<operations>
    <operation name="move">
        <set>
            <ins mnemonic="xor">
                <reg1>dst</reg1>
                <reg2>dst</reg2>
            </ins>
            <ins mnemonic="add">
                <reg1>dst</reg1>
                <reg2>src</reg2>
            </ins>
        </set>
    </operation>
</operations>
```
El fichero XML permite establecer en cada registro de una instrucción los siguiente valores:

* dst: registro destino
* src: registro fuente
* aux: registro auxiliar (sólo se puede especificar uno por conjunto o set)
* [dst]: dirección de destino alojada en un registro
* [src]: dirección de fuente alojada en un registro
* {eax, ebx, ecx...}: registro específico de propósito general
* {[eax, ebx, ecx...]}: dirección alojada en un registro específico de propósito general
* &lt;reg{1,2} value ="0xFFFFFFFF">: valor obligatorio del registro

### Automatizar la creación de ataques ROP
Mediante la opción --ropattack &lt;path> se puede especificar un fichero de texto plano en el que se especifique un ataque ROP a través de las operaciones definidas en el XML. Un ejemplo de automatización es el siguiente:
```
lc(reg1)
lc(reg2)
sub(reg2, reg1)
lc(reg3)
store(reg3, reg2)
```

### Licencia
La herramienta está publicada bajo la licencia GNU GPLv3, se puede acceder a la licencia en los ficheros fuente.