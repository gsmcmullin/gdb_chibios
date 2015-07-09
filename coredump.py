# GDB plugin for generation of core dumps on bare-metal ARM.
#
# This replaces GDB's 'gcore' command.  A new GDB parameter
# 'gcore-file-name' is added to set the name of the core file to be dumped.
# The module also hooks stop events on SIGSEGV to core dump.
#
# The generated core dumps should be used with gdb-multiarch on Debian
# or similar systems.  The GDB provided with gcc-arm-embedded is not capable
# of reading a core file.  Only the general purpose registers are available
# from the core dump.

# Reference:
# - Tool Interface Standard (TIS) Executable and Linking Format (ELF)
#   Specification Version 1.2 (May 1995)
#   http://refspecs.linuxbase.org/elf/elf.pdf

import gdb
import struct
import time
import chibios
import corefile

SIGINT = 2
SIGSEGV = 11

class CommandGCore(gdb.Command):
  """Replacemenet 'gcore' function to generate ARM core dumps."""
  def __init__(self):
    super(CommandGCore, self).__init__('gcore', gdb.COMMAND_USER)

  def invoke(self, arg='', from_tty=False, sig=SIGINT):
    # Iterate over each ChibiOS thread and add a PRSTATUS note descriptor
    # for the general-purposes registers.
    notes = ''
    for t in chibios.thread_cache:
      prstatus = corefile.ARM_prstatus()
      if t.active: # Only set signal for the running thread
        prstatus.pr_cursig = sig
      prstatus.pr_pid = t.lwp
      # Is it possible to include a target register description?
      notes += corefile.note_desc("CORE", 1, prstatus.dumps() +
                                  struct.pack("<19L", *t.regs))

    inf = gdb.selected_inferior()
    # How do we query the memory map from GDB?
    # TODO: Use 'info mem'
    ram = inf.read_memory(0x20000000, 128*1024)
    ccmram = inf.read_memory(0x10000000, 64*1024)
    scs = inf.read_memory(0xE000ED00, 0x40)

    core = corefile.CoreFile()
    core.set_type(corefile.ET_CORE)
    core.set_machine(0x28) #ARM
    core.add_program(corefile.PT_NOTE, 0, notes)
    core.add_program(corefile.PT_LOAD, 0x10000000, ccmram)
    core.add_program(corefile.PT_LOAD, 0x20000000, ram)
    core.add_program(corefile.PT_LOAD, 0xE000ED00, scs)

    fn = arg if arg else gcore_file_name.value
    fn += "-" + time.strftime("%y%m%d-%H%M%S")
    core.dump(open(fn, "w"))
    print "(core dumped to %r)" % fn

gcore = CommandGCore()

class ParameterGCoreFileName(gdb.Parameter):
  def __init__(self):
    self.set_doc = "Set gcore default name"
    self.show_doc = "Show gcore default name"
    gdb.Parameter.__init__(self, "gcore-file-name", gdb.COMMAND_SUPPORT,
                           gdb.PARAM_STRING)
    self.value = "core"
  def get_set_string(self):
    return "Default gcore name is %r" % self.value
  def get_show_string(self, svalue):
    return "Default gcore name is %r" % self.value

gcore_file_name = ParameterGCoreFileName()

def stop_handler(event):
  """Dump core file when GDB's inferior is stopped with SIGSEGV."""
  if type(event) is not gdb.SignalEvent:
    return
  if event.stop_signal == "SIGSEGV":
    gcore.invoke(sig=SIGSEGV)
gdb.events.stop.connect(stop_handler)

gdb.execute("set mem inaccessible-by-default off")
gdb.execute("handle SIGSEGV stop nopass")

