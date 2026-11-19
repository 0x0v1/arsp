arsp
====

arsp (aarch64 Remote Serial Protocol) is a small GDB Remote Serial Protocol
client for aarch64 targets served by lldb-server in gdbserver mode.  It reads and writes memory and registers, sets
software breakpoints, single-steps, and injects function calls on a stopped
thread.  It has no dependencies outside the Go standard library and carries no
knowledge of any particular target: addresses and symbols are the caller's.

It works out of process, through the kernel's ptrace-backed debug stub, so it
never allocates executable memory or patches code in the target.  That is the
point: on hardened aarch64 (MTE, BTI, W^X / SELinux no-execmem, PAC) in-process
instrumentation such as Frida cannot inject, while a debugger stub still can.
arsp also masks the top byte of every address before comparing it, so calls and
breakpoints behave correctly under MTE tagging and PAC signing, and it talks to
lldb-server by register number rather than fighting its target.xml.


uses
----

  reaching a function on a device where Frida will not load, by calling it
  directly on a thread stopped under lldb-server.

  exercising a native parser or handler with controlled arguments, reading the
  return value out of x0 and the fault, if any, out of the stop reply.

  reading and writing process memory and registers from a static Go binary,
  with no python or lldb scripting runtime on the host.

  driving the same stub from a larger Go tool by embedding the package, or by
  hand with the CLI: arsp regs, arsp readmem, arsp call.

  scripting breakpoint-and-continue loops where lldb's own scripting is heavier
  than the task warrants.


build
-----

  go install github.com/0x0v1/arsp/cmd/arsp@latest

  adb forward tcp:1234 tcp:1234
  adb shell su -c 'lldb-server gdbserver :1234 --attach <pid>'
  arsp regs    -addr 127.0.0.1:1234
  arsp readmem -addr 127.0.0.1:1234 -at 0x7fff000000 -n 64
  arsp call    -addr 127.0.0.1:1234 -pc 0x7000001234 -args 1,0x4141


arsp is a debugger, not a sandbox.  It does to a thread exactly what it is told,
including crash it.  MIT licensed.
