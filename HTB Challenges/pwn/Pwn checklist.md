# Introduction

In this document, I am aiming to create a checklist of all the vulnerabilities/exploits that I came across/learnt.

# Checklist
- [ ] Format String Attack
- check for input sanitization existence
- [ ] Integer Overflow
- check for integer conversion, especially from a datatype that stores more bytes to one that stores less.

- [ ] Buffer Overflow
- check for unsafe user input reading functions.
- use `pwndbg` to analyze.

- [ ] Executable stack
Run `checksec`.
