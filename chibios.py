import gdb
import struct

# Global (module) state

# Backup of ARM registers ([r0-15, xpsr] or empty list for unknown)
reg_cache = []
# List of ChibiOS threads (ChibiThread objects)
thread_cache = []
# Currently executing thread (gdb.Value pointer to thread struct, or None)
currp = None

class ChibiThread(object):
  next_lwp = 1
  def __init__(self, tp):
    self.tp = tp
    self.name = tp.dereference()['p_name'].string()
    self.lwp = ChibiThread.next_lwp
    ChibiThread.next_lwp += 1
    self._update()

  def _update_frame(self):
    # We used to do set_cpu_regs() here and then get a gdb.Frame, but that's
    # really slow.  We don't care too much about the detail here, so just
    # lookup the function name.
    self.block = gdb.block_for_pc(self.regs[15])
    while self.block.function is None:
      self.block = self.block.superblock
    self.frame_str = "0x%X in %s ()" % (self.regs[15], self.block.function)

  def _update(self):
    # Update name in case it changed
    self.name = self.tp.dereference()['p_name'].string()
    self.regs = list(reg_cache) # Make a copy of the list
    if self.tp == currp:
      self.active = True
      self._update_frame()
      return

    self.active = False
    r13 = self.tp.dereference()['p_ctx']['r13']
    longtype = gdb.lookup_type('unsigned long')
    self.regs[13] = int((r13+1).cast(longtype))
    self.regs[15] = int(r13['lr'].cast(longtype))
    for i in range(4, 12):
      self.regs[i] = int(r13['r%d'%i].cast(longtype))
    self._update_frame()
    # Attempt the nasty unwind out of _port_switch_from_isr
    # get function for pc
    if str(self.block.function) == "_port_switch_from_isr":
      #if here pop exception frame from stack...
      ex_struct = "<8L"
      stack = gdb.selected_inferior().read_memory(self.regs[13],
                                                  struct.calcsize(ex_struct))
      stack = struct.unpack(ex_struct, stack)
      self.regs[:4] = stack[:4]
      self.regs[12] = stack[4]
      self.regs[14] = stack[5]
      self.regs[15] = stack[6]
      self.regs[16] = stack[7]
      # TODO check for extended/standard frame
      self.regs[13] += 0x68 # size of extended frame
      self._update_frame()

def get_cpu_regs():
  """Return the current state of general purpose registers"""
  gdb.newest_frame().select()
  regs = [0] * 19
  for i in range(16):
    regs[i] = int(gdb.parse_and_eval("(unsigned long)$r%d" % i))
  regs[16] = int(gdb.parse_and_eval("(unsigned long)$xpsr"))
  return regs

def set_cpu_regs(regs):
  """Set the current state of general purpose registers"""
  gdb.newest_frame().select()
  for i in range(16):
    gdb.execute("set $r%d = %d" % (i, regs[i]))

  # Trying to set xpsr sometimes fails?
  # Don't bomb here, we still need to set the stack pointer
  try:
    gdb.execute("set $xpsr = %d" % regs[16])
  except:
    print("Failed to set xpsr")

  # Write stack pointer from $sp to $psp or $msp for it to take effect
  if regs[16] & 0xff:
    # In an exception handler, use MSP
    gdb.execute("set $msp = %d" % regs[13])
  else:
    # In a thread, use PSP
    gdb.execute("set $psp = %d" % regs[13])

def stop_handler(event=None):
  """Called by gdb when the inferior stops on a signal or breakpoint.
     This updates our register cache, and iterates over the thread
     list updating our view of threads and their stack frames.  It
     announces new thread started since the last resume."""
  global reg_cache
  global thread_cache
  global currp
  # Save register cache
  reg_cache = get_cpu_regs()
  try:
    currp = gdb.parse_and_eval('currp')
  except:
    currp = None
    thread_cache = []
    return

  # Update our list of ChibiOS threads from target
  tmp_thread_list = [gdb.parse_and_eval('rlist.r_newer')]
  while True:
    tp = tmp_thread_list[-1].dereference()['p_newer']
    if (tp == tmp_thread_list[0]) or (tp.dereference()['p_ctx']['r13'] == 0):
      break
    tmp_thread_list.append(tp)
  # Announce dead threads
  for t in thread_cache:
    t._update()
  # Announce new threads, we compare by str(tp) because gdb.Values are different
  old_thread_set = set(str(t.tp) for t in thread_cache)
  for t in tmp_thread_list:
    if str(t) not in old_thread_set:
      ct = ChibiThread(t)
      thread_cache.append(ct)
      print("[New thread '%s']" % ct.name)
  set_cpu_regs(reg_cache)

gdb.events.stop.connect(stop_handler)

def cont_handler(event):
  """Called by gdb when the inferior is resumed.  Here we restore the CPU
     core registers to the values in our register cache in case we've switched
     threads from the debugger."""
  if reg_cache:
    set_cpu_regs(reg_cache)
gdb.events.cont.connect(cont_handler)

def exit_handler(event):
  """Called when the inferior exits.  Were we just discard all our knowledge
     about the target state.  This is needed for 'run' where the inferior
     is killed, and then resumed, to prevent cont_handler writing junk over
     the new inferior's registers."""
  global reg_cache
  global thread_cache
  global currp
  reg_cache = []
  currp = None
  thread_cache = []
  ChibiThread.next_lwp = 1
gdb.events.exited.connect(exit_handler)

class CommandInfoThreads(gdb.Command):
  """Replacement for gdb's 'info threads' command.  Print a list of active
     threads and summaries of their stack frames."""
  def __init__(self):
    super(CommandInfoThreads, self).__init__('info threads', gdb.COMMAND_USER)

  def invoke(self, arg, from_tty=False):
    print("  Id   Target Id            Frame")
    for i in range(len(thread_cache)):
      print("%c %-4d %-20s %s" % ('*' if thread_cache[i].active else ' ',
                 thread_cache[i].lwp, thread_cache[i].name,
                 thread_cache[i].frame_str))
cmd_info_threads = CommandInfoThreads()

class CommandThread(gdb.Command):
  """Replacement for gdb's 'thread' command.  Used to select a
     thread for debugging."""
  def __init__(self):
    super(CommandThread, self).__init__('thread', gdb.COMMAND_USER)

  def invoke(self, arg, from_tty=False):
    if not arg:
      for thread in thread_cache:
        if thread.active:
          print('[Current thread is %d (%s)]' % (thread.lwp, thread.name))
          return

    old_lwp = 0
    found = False
    for thread in thread_cache:
      if thread.lwp == int(arg):
        thread.active = True
        found = True
        set_cpu_regs(thread.regs)
      elif thread.active:
        old_lwp = thread.lwp
        thread.active = False
    if not found:
      print("Thread ID %d not known." % int(arg))
      for thread in thread_cache:
        if thread.lwp == old_lwp:
          thread.active = True

cmd_thread = CommandThread()

try:
  # Don't cry if this fails...
  stop_handler()
except:
  pass

