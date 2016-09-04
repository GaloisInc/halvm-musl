#!/bin/sh

UNAMEP=`uname -p`
if [ "${UNAMEP}" == "x86_64" ]; then
  ARCH="x86_64"
else
  ARCH="i386"
fi

ln -sf ${PWD}/arch/${ARCH}/bits   ${PWD}/arch/halvm/bits
ln -sf ${PWD}/crt/${ARCH}         ${PWD}/crt/halvm
ln -sf ${PWD}/src/fenv/${ARCH}    ${PWD}/src/fenv/halvm
ln -sf ${PWD}/src/math/${ARCH}    ${PWD}/src/math/halvm
ln -sf ${PWD}/src/process/${ARCH} ${PWD}/src/process/halvm
ln -sf ${PWD}/src/setjmp/${ARCH}  ${PWD}/src/setjmp/halvm
ln -sf ${PWD}/src/signal/${ARCH}  ${PWD}/src/signal/halvm
ln -sf ${PWD}/src/string/${ARCH}  ${PWD}/src/string/halvm

ln -sf ${PWD}/arch/${ARCH}/reloc.h       ${PWD}/arch/halvm/reloc.h
ln -sf ${PWD}/arch/${ARCH}/atomic_arch.h ${PWD}/arch/halvm/atomic_arch.h
