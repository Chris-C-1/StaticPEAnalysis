
Static analysis framework for 32 bit Windows binaries (Portable Executables).
Performs PE header analysis, entropy analysis, plaintext extraction
and then disassembles the binary, finds procedures and builds the call
graph. You WILL have to add your own analysis functions. Currently, the only
analysis is that the five procedures with the most incoming calls are (partially)
printed. PE header analysis, entropy analysis, plaintext extraction is generic and should
work fine on any 32 bit Windows binary

This framework was built to analyze a few particular binaries and worked very well for that.
I have removed the functionality specific to those binaries. Not much testing has been performed
outside those binaries, but it SHOULD (...) work on any Win 32 binary.

Dependencies:
distorm3 disassembler library, https://code.google.com/p/distorm/
pefile PE header library, https://code.google.com/p/pefile/