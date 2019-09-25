# flareon6_NES_ghidra_loader
iNES [Ghidra](https://ghidra-sre.org/) loader for level 8 from [Flare-on 6 challenge](https://www.fireeye.com/blog/threat-research/2019/07/announcing-the-sixth-annual-flare-on-challenge.html)

<img width="377" alt="ghidra1" src="https://user-images.githubusercontent.com/4478350/65594754-fdbbb780-dfc5-11e9-83c5-3f76d0cca7f6.PNG">

<img width="950" alt="ghidra2" src="https://user-images.githubusercontent.com/4478350/65594774-00b6a800-dfc6-11e9-8127-19f1a857f000.PNG">


## Insatllation
Just copy the zip in the `dist` directory to `<Ghidra_ROOT_DIR>/Extensions/Ghidra/` folder.  
Check out the instructions in Ghidra's [official website](https://ghidra-sre.org/InstallationGuide.html#Extensions) for more details.  

## Developing  
I use Eclipse and the GhidraDev plugin to develop the plugin loader.  
Here's a [useful article](https://habr.com/en/post/443318/) if you're interested in developing the plugin.  

## Notice  
This plugin loader was developed for solving the level 8 of the Flare-on 6 challenge.  
**!! It can only load the first PRG ROM into Ghidra. !!**  
I'm too lazy to develop a general-working iNES loader :P  
Feel free to fork the repo and develop it yourself.  

## Credits  
Some references I used for developing the plugin:  
* [NES DEV](http://wiki.nesdev.com/w/index.php/INES)  
* [NES ROM Quickstart](https://sadistech.com/nesromtool/romdoc.html)  
* NES spec from radare2: [link1](https://github.com/radareorg/radare2/blob/master/libr/bin/p/bin_nes.c), [link2](https://github.com/radareorg/radare2/blob/master/libr/bin/format/nes/nes_specs.h)
* [VGKintsugi's Ghidra-SegaMasterSystem-Loader](https://github.com/VGKintsugi/Ghidra-SegaMasterSystem-Loader)  
* [Ghidra Advanced Development Class](https://ghidra.re/courses/GhidraClass/AdvancedDevelopment/GhidraAdvancedDevelopment.html)  
* [Writing a wasm loader for Ghidra. Part 1: Problem statement and setting up environment](https://habr.com/en/post/443318/)
