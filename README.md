# EasyROP
This Python tool allows you to search gadgets, operations formed by gadgets and generate automatic ROP chains in Portable Executable (PE). EasyROP is based in Capstone Disassembly Framework to search gadgets.

### Install
EasyROP needs [Capstone](http://www.capstone-engine.org/download.html) and [pefile](https://pypi.python.org/pypi/pefile/) installation.

Once you solve this depencies, EasyROP can be used as:
```
$ python EasyROP.py
```

### Use
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

### Operations
This operations are high level operations built by gadgets. The following is an example to move a value from one register to another:
```
xchg dst, src
```
```
xor dst, dst
add dst, src
```

### Specification of operations
Following the next DTD you can specify your own operations through a XML file:
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
This XML structure allows you to define register value of each instruction:

* dst: destination register
* src: source register
* aux: auxiliary register (only one by set)
* [dst]: destination direction allocated in a register
* [src]: source direction allocated in a register
* {eax, ebx, ecx...}: specific register
* {[eax, ebx, ecx...]}: direction allocated in a specific register
* &lt;reg{1,2} value ="0xFFFFFFFF">: mandatory value of register

### Automatic ROP chains generation
Through the --ropattack &lt;path> option you can specify in a plaintex file a ROP attack composed by operations defined in the XML. An example:
```
lc(reg1)
lc(reg2)
sub(reg2, reg1)
lc(reg3)
store(reg3, reg2)
```

### License
This tool is published under the GNU GPLv3 license.