# laa-tool

A quick hack to inspect or set/unset the Large Address Awareness flag for 
32-bit Microsoft PE executables.

Specifically, I wrote it so that I could play Dragon Age: Origins on a 
modern system with acceptable resolution (without it crashing at Ostagar).
It is heavily cribbed from a Visual Basic for Access utility written by
Philipp Stiefel (phil@codekabinett.com) of [codekabinett.com](https://www.codekabinett.com/)

Run it without the set/unset flags to inpect the LAA status.

`python laa-tool.py <path to executable`

To obtain a safe version of Python, consider installing [Chocolatey](https://chocolatey.org)
and installing the official Python package listed thereon.

If this breaks your favourite toys, that's on  you. Use caution.
