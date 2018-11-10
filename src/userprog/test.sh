#!/bin/bash

make clean
make
cd build
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
pintos -p ../../examples/echo -a echo -- -q
cd ..
