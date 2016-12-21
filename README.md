Quickie WIP ransomware program.

Please use for good (aka security learning and teaching).

If it is not obvious:

!!!DO NOT RUN ON A MACHINE YOU CARE ABOUT OR A MACHINE THAT IS NOT YOURS!!!

This is completely untested on Windows.

Encryption and file traversal seems to be working.

Need to test the whole secure deletion thing (shameless copy and pasted and not tested at all (audited the code and compiled...but never run...).

Secure deletion code required some cleanup...so...yea...

To do:

-Add https via mongoose to send ransom info and receive key/iv.
-Build simple server to accept ransom info and send back a random key/iv.
-Test on Winblows.
