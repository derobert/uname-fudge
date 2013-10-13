uname-fudge
===========

Use ptrace to fudge the result of `uname(2)`. Intended to placate programs
that have an acrimonious relationship with two-place kernel versions
(such as the 3ware utilities).

Running `tw_cli` on a two-place-version kernel (such as 3.10, instead of
3.10.0) results in a segfault. Of course, Linux 3.0.0 was the last one
to use a three-place version; 3.1 was just 3.1.

Here is how it's used:

    $ uname -r
    3.10-3-686-pae
    $ ./uname-fudge -r 3.10.0-3-686-pae -- uname -r
    3.10.0-3-686-pae

The options mirror those of the `uname(1)` command, except taking a
string as an argument:

 * -s STRING - System name ("Linux")
 * -n STRING - Node name (often hostname)
 * -r STRING - Release
 * -v STRING - Version (often your distro's version)
 * -m STRING - Machine (architecture)
