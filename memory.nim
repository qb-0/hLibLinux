import 
  os, tables, strformat, 
  strutils, sequtils, posix,
  regex

type
  Process* = object
    name*: string
    pid*: int
    baseAddr*: ByteAddress
    modules*: Table[string, Module]

  Module* = object
    baseAddr*: ByteAddress
    moduleSize*: int
    regions*: seq[tuple[s: ByteAddress, e: ByteAddress, size: int]]

proc process_vm_readv(pid: int, local_iov: ptr IOVec, liovcnt: culong, remote_iov: ptr IOVec, riovcnt: culong, flags: culong): cint {.importc, header: "<sys/uio.h>", discardable.}
proc process_vm_writev(pid: int, local_iov: ptr IOVec, liovcnt: culong, remote_iov: ptr IOVec, riovcnt: culong, flags: culong): cint {.importc, header: "<sys/uio.h>", discardable.}

proc getModules(pid: int): Table[string, Module] =
  for l in lines(fmt"/proc/{pid}/maps"):
    let 
      s = l.split()
      name = s[^1].split("/")[^1]
    if name notin result:
      result[name] = Module()
    let hSplit = s[0].split("-")
    if result[name].baseAddr == 0:
      result[name].baseAddr = parseHexInt(hSplit[0])
    result[name].regions.add(
      (
        s: parseHexInt(hSplit[0]), 
        e: parseHexInt(hSplit[1]),
        size: parseHexInt(hSplit[1]) - parseHexInt(hSplit[0]),
      )
    )
    result[name].moduleSize = result[name].regions[^1].e - result[name].baseAddr

proc read*(a: Process, address: ByteAddress, t: typedesc): t =
  var
    iosrc, iodst: IOVec
    size = sizeof(t).uint

  iodst.iov_base = result.addr
  iodst.iov_len = size
  iosrc.iov_base = cast[pointer](address)
  iosrc.iov_len = size
  discard process_vm_readv(a.pid, iodst.addr, 1, iosrc.addr, 1, 0)

proc write*(a: Process, address: ByteAddress, data: auto): int {.discardable.} =
  var
    iosrc, iodst: IOVec
    size = sizeof(data).uint
    d = data

  iosrc.iov_base = d.addr
  iosrc.iov_len = size
  iodst.iov_base = cast[pointer](address)
  iodst.iov_len = size
  process_vm_writev(a.pid, iosrc.addr, 1, iodst.addr, 1, 0)

proc readString*(a: Process, address: ByteAddress): string =
  let b = a.read(address, array[0..100, char])
  result = $cast[cstring](b[0].unsafeAddr)

proc readSeq*(a: Process, address: ByteAddress, size: uint, t: typedesc = byte): seq[t] =
  result = newSeq[t](size)
  var iosrc, iodst: IOVec

  iodst.iov_base = result[0].addr
  iodst.iov_len = size * sizeof(t).uint
  iosrc.iov_base = cast[pointer](address)
  iosrc.iov_len = size * sizeof(t).uint
  process_vm_readv(a.pid, iodst.addr, 1, iosrc.addr, 1, 0)

proc processByName*(name: string): Process =
  let allFiles = toSeq(walkDir("/proc", relative = true))
  for pid in mapIt(filterIt(allFiles, isDigit(it.path[0])), parseInt(it.path)):
      let procName = readLines(fmt"/proc/{pid}/status", 1)[0].split()[1]
      if name in procName:
        result.name = procName
        result.pid = pid
        result.modules = getModules(pid)
        result.baseAddr = result.modules[result.name].baseAddr
        return
  raise newException(IOError, fmt"Process not found ({name})")

proc processByPid*(pid: int): Process =
  try:
    result.name = readLines(fmt"/proc/{pid}/status", 1)[0].split()[1]
    result.pid = pid
    result.modules = getModules(pid)
    result.baseAddr = result.modules[result.name].baseAddr
  except IOError:
    raise newException(IOError, fmt"Pid ({pid}) does not exist")

proc aobScan*(a: Process, pattern: string, module: Module): ByteAddress =
  var 
    curAddr = module.baseAddr
    rePattern = re(
      pattern.toUpper().multiReplace((" ", ""), ("??", "?"), ("?", ".."), ("*", ".."))
    )

  for r in module.regions:
    curAddr += r.size
    let byteString = cast[string](a.readSeq(r.s, r.size.uint)).toHex()
    let b = byteString.findAllBounds(rePattern)
    if b.len != 0:
      return b[0].a div 2 + curAddr

proc nopCode*(a: Process, address: ByteAddress, length: int = 1) =
  for i in 0..length-1:
    a.write(address + i, 0x90.byte)

# Internal

proc intProcess*: Process =
  processByPid(getPid())

proc memRead*(address: ByteAddress, t: typedesc): t =
  cast[ptr t](address)[]

proc memWrite*(address: ByteAddress, data: auto) =
  cast[ptr typeof(data)](address)[] = data

proc memReadString*(address: ByteAddress): string =
  var r = memRead(address, array[0..50, char])
  $cast[cstring](r[0].unsafeAddr)