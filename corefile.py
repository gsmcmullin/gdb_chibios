import struct
import sys

ET_NONE = 0
ET_EXEC = 2
ET_CORE = 4

PT_NULL = 0
PT_LOAD = 1
PT_NOTE = 4

# This nasty struct stuff could be replaced with construct, at the cost
# of adding a horrible dependency.  It may be possible to use ctypes.Structure
# but it wasn't immediately obvious how.
class Struct(object):
  def __init__(self, buf=None):
    if buf is None:
      buf = b'\0' * self.sizeof()
    fields = struct.unpack(self.__class__.fmt, buf[:self.sizeof()])
    self.__dict__.update(zip(self.__class__.fields, fields))

  def sizeof(self):
    return struct.calcsize(self.__class__.fmt)

  def dumps(self):
    keys =  self.__class__.fields
    if sys.version_info > (3, 0):
      # Convert strings into bytearrays if this is Python 3
      for k in keys:
        if type(self.__dict__[k]) is str:
          self.__dict__[k] = bytearray(self.__dict__[k], encoding='ascii')
    return struct.pack(self.__class__.fmt, *(self.__dict__[k] for k in keys))

  def __str__(self):
    keys =  self.__class__.fields
    return (self.__class__.__name__ + "({" +
        ", ".join("%s:%r" % (k, self.__dict__[k]) for k in keys) +
        "})")

class Elf32_Ehdr(Struct):
  """ELF32 File header"""
  fields = ("e_ident",
            "e_type",
            "e_machine",
            "e_version",
            "e_entry",
            "e_phoff",
            "e_shoff",
            "e_flags",
            "e_ehsize",
            "e_phentsize",
            "e_phnum",
            "e_shentsize",
            "e_shnum",
            "e_shstrndx")
  fmt = "<16sHHLLLLLHHHHHH"

  def __init__(self, buf=None):
    Struct.__init__(self, buf)
    if buf is None:
      # Fill in sane ELF header for LSB32
      self.e_ident = "\x7fELF\1\1\1\0\0\0\0\0\0\0\0\0"
      self.e_version = 1
      self.e_ehsize = self.sizeof()

class Elf32_Phdr(Struct):
  """ELF32 Program Header"""
  fields = ("p_type",
            "p_offset",
            "p_vaddr",
            "p_paddr",
            "p_filesz",
            "p_memsz",
            "p_flags",
            "p_align")
  fmt = "<LLLLLLLL"

class ARM_prstatus(Struct):
  """ARM Program Status structure"""
  # Only pr_cursig and pr_pid are read by bfd
  # Structure followed by 72 bytes representing general-purpose registers
  # check elf32-arm.c in libbfd for details
  fields = ("si_signo", "si_code", "si_errno",
            "pr_cursig", # Current signal
            "pr_pad0",
            "pr_sigpend",
            "pr_sighold",
            "pr_pid", # LWP ID
            "pr_ppid",
            "pr_pgrp",
            "pr_sid",
            "pr_utime",
            "pr_stime",
            "pr_cutime",
            "pr_cstime")
  fmt = "<3LHHLLLLLLQQQQ"

class CoreFile(object):
  """Beginnings of a ELF file object.
     Only supports program headers (segments) used by core files and not
     Sections used by executables."""
  def __init__(self, fileobj=None):
    """Create a core object (from a file image)"""
    ehdr = self._ehdr = Elf32_Ehdr(fileobj)
    self._phdr = []
    for i in range(self._ehdr.e_phnum):
      chunk = fileobj[ehdr.e_phoff + i * ehdr.e_phentsize:
                      ehdr.e_phoff + (i+1) * ehdr.e_phentsize]
      phdr = Elf32_Phdr(chunk)
      phdr.data = fileobj[phdr.p_offset:phdr.p_offset + phdr.p_filesz]
      self._phdr.append(phdr)

  def update_headers(self):
    """Update header fields after segments are modified."""
    ehdr = self._ehdr
    if self._phdr:
      ehdr.e_phoff = ehdr.sizeof()
      ehdr.e_phentsize = self._phdr[0].sizeof()
      ehdr.e_phnum = len(self._phdr)
    else:
      ehdr.e_phoff = 0
      ehdr.e_phentsize = 0
      ehdr.e_phnum = 0
    ofs = ehdr.e_phoff + ehdr.e_phentsize * ehdr.e_phnum
    for phdr in self._phdr:
      phdr.p_offset = ofs
      phdr.p_filesz = len(phdr.data)
      if phdr.p_filesz > phdr.p_memsz:
        phdr.p_memsz = phdr.p_filesz
      ofs += phdr.p_filesz

  def dump(self, f):
    """Write the object to an ELF file."""
    self.update_headers()
    f.write(self._ehdr.dumps())
    for phdr in self._phdr:
      f.write(phdr.dumps())
    for phdr in self._phdr:
      f.write(phdr.data)

  def set_type(self, t):
    """Set the file type in the file header."""
    self._ehdr.e_type = t

  def set_machine(self, m):
    """Set the machine type in the file header."""
    self._ehdr.e_machine = m

  def add_program(self, p_type, vaddr, data):
    """Add a program header (segment) to the object."""
    phdr = Elf32_Phdr()
    phdr.p_type = p_type
    phdr.p_vaddr = vaddr
    phdr.p_filesz = phdr.p_memsz = len(data)
    phdr.data = data
    self._phdr.append(phdr)

  def __str__(self):
    return str(self._ehdr) + "\n" + "\n".join(str(phdr) for phdr in self._phdr)

def note_desc(name, type, desc):
  """Conveninece function to format a note descriptor.
     All note descriptors must be concatenated and added to a
     PT_NOTE segment."""
  name += '\0'
  header = struct.pack("<LLL", len(name), len(desc), type)
  # pad up to 4 byte alignment
  name += ((4 - len(name)) % 4) * '\0'
  desc += ((4 - len(desc)) % 4) * '\0'
  return header + name + desc

if __name__ == "__main__":
  cf = CoreFile()
  cf.set_type(ET_CORE)
  cf.set_machine(0x28)
  cf.dump(open("core", "wb"))

