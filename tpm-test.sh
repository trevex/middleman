#!/usr/bin/env bash

# yaourt -S ibm-sw-tpm2 tpm2-tss tpm2-abrmd tpm2-tools
# tpm_server
# tpm2-abrmd --allow-root --tcti=mssim
tpm2_takeownership -o "" -c
tpm2_createprimary -H o -g sha256 -G rsa -C po.ctx
tpm2_create -c po.ctx -G rsa -g sha256 -u key.pub -r key.priv
tpm2_load -c po.ctx -u key.pub -r key.priv -n key.name -C obj.ctx
vim data.in
tpm2_rsaencrypt -c obj.ctx -o data.enc data.in
tpm2_rsadecrypt -c obj.ctx -o data.out -I data.enc
cat data.out
# tpm2_load -c default.ctx -u key.pub -r key.priv -n key2.name -C obj2.ctx
# tpm2_rsadecrypt -c obj2.ctx -o data2.out -I data.enc
# cat data2.out
 1184  tpm2_createprimary -H o -g sha256 -G rsa -C po.ctx
 1185  tpm2_evictcontrol -A o -c po.ctx -S 0x81010009
 1186  tpm2_create -g sha256 -G rsa -u obj.pub -r obj.priv -H 0x81010009 -C obj.ctx
 1187  tpm2_create -g sha256 -G rsa -u obj.pub -r obj.priv -H 0x81010009
 1188  tpm2_load -H 0x81010009 -u obj.pub -r obj.priv -C obj.ctx
 1189  tpm2_rsaencrypt -c obj.ctx -o data.enc data.in
 1190  tpm2_rsadecrypt -c obj.ctx -o data.out -I data.en
