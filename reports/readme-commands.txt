=== MachGraph README Commands Replay (README.md + README.zh-CN.md) ===
Date (UTC): 2026-11-22T11:48:51Z
macOS:      macOS 27.0.1 (26A434) arm64

[PASS] README.md and README.zh-CN.md contain the same 32 commands (22 MachGraph invocations)
[PASS] README.md: all 13 MachGraph options it uses are listed in --help (en + zh): --address --asm --at --count --demo --force --function --help --json --lang --output --slice --symbol
[PASS] README.zh-CN.md: all 13 MachGraph options it uses are listed in --help (en + zh): --address --asm --at --count --demo --force --function --help --json --lang --output --slice --symbol
[PASS] every MachGraph example starts with a subcommand listed in --help; none can open the desktop app
$ .build/debug/MachGraph info /bin/ls
  -> OK (ls, 5 segments, 11 sections)
$ .build/debug/MachGraph info /bin/ls --json
  -> OK (JSON fileName=ls, isDemo=false)
$ .build/debug/MachGraph segments /bin/ls
  -> OK (__TEXT .. __LINKEDIT)
$ .build/debug/MachGraph fixups /bin/ls --json
  -> OK (113 fixups)
$ .build/debug/MachGraph symbols /bin/ls
  -> OK (symtab and [inferred:...] listed separately)
$ .build/debug/MachGraph codesign /bin/ls
  -> OK (Signed=true Identifier=com.apple.ls)
$ .build/debug/MachGraph codesign /usr/bin/ssh --json
  -> OK (exit 0, valid JSON (no specific expectation registered))
$ .build/debug/MachGraph demangle '_$sSiN' __Z3fooi _ZeroFilesTested --json
  -> OK (exit 0, valid JSON (no specific expectation registered))
$ printf '_$sSiN\n__Z12set_darkbooti.cold.1\n_main\n' | .build/debug/MachGraph demangle
  -> OK (exit 0, non-empty output (no specific expectation registered))
$ .build/debug/MachGraph objc /System/Applications/Calculator.app/Contents/MacOS/Calculator --json
  -> OK (exit 0, valid JSON (no specific expectation registered))
$ .build/debug/MachGraph xrefs /bin/ls --json
  -> OK (exit 0, valid JSON (no specific expectation registered))
$ .build/debug/MachGraph disasm /bin/ls --symbol entry --count 12
  -> OK (12 instructions from the /bin/ls entry function)
$ .build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10
  -> OK (10 instructions starting at 0x100000460)
$ .build/debug/MachGraph cfg /bin/ls --json
  -> OK (schema=machgraph.cfg/1, 133 functions (50 LC_FUNCTION_STARTS, 1 inline jump table), 871 blocks, 1110 edges)
$ .build/debug/MachGraph cfg /bin/ls --symbol _entry --json
  -> OK (schema=machgraph.cfg/1, _entry: 154 blocks, 259 edges, 1 loop, 1 jump table; missing --symbol exits 1 with empty stdout)
$ .build/debug/MachGraph cfg-dot /bin/ls --symbol _entry
  -> OK (Graphviz DOT for _entry (digraph "entry"))
$ cp Fixtures/demo_arm64_sample /tmp/machgraph_readme_sample
  -> OK (exit 0)
$ .build/debug/MachGraph patch-asm /tmp/machgraph_readme_sample --address 0x100000460 --asm "pacibsp; stp x29, x30, [sp, #-16]!; mov x0, #42; retab" --force --output /tmp/machgraph_readme_patched --json
  -> OK (16 bytes assembled, valid=true, codesign --verify --strict passed)
$ rm -f /tmp/machgraph_readme_sample /tmp/machgraph_readme_patched
  -> OK (exit 0)
$ .build/debug/MachGraph asm --at 0x100000460 --asm "stp x29, x30, [sp, #-16]!; mov x0, #42; b .+8" --json
  -> OK (3 ok words: a9bf7bfd, d2800540, 14000002 @ 0x100000460..0x100000468)
$ .build/debug/MachGraph export-html /bin/ls --output /tmp/machgraph_ls_triage.html
  -> OK (45787 bytes of HTML containing the SHA-256 of /bin/ls)
$ rm -f /tmp/machgraph_ls_triage.html
  -> OK (exit 0)
$ .build/debug/MachGraph --help --lang zh
  -> OK (Chinese help)
$ .build/debug/MachGraph info --demo --lang zh
  -> OK ([演示数据] banner present)
$ printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mach_inspect_binary","arguments":{"binaryPath":"/bin/ls"}}}\n' | .build/debug/MachGraph mcp
  -> OK (mach_inspect_binary returned the /bin/ls summary, isError=false)
[NOT REPLAYED] swift build --product MachGraph  (build entry point)
[NOT REPLAYED] ./Scripts/acceptance/m0-quick.sh  (build/test entry point; ./Scripts/acceptance/m0-quick.sh exists and is executable)
[NOT REPLAYED] ./Scripts/acceptance/readme-commands.sh  (build/test entry point; ./Scripts/acceptance/readme-commands.sh exists and is executable)
[NOT REPLAYED] ./Scripts/test.sh scope MachBinaryFormats MachA64Decoder MachCFGEngine MachHeadlessCLI  (build/test entry point; ./Scripts/test.sh exists and is executable)
[NOT REPLAYED] ./Scripts/test.sh milestone 0  (build/test entry point; ./Scripts/test.sh exists and is executable)
[NOT REPLAYED] ./Scripts/test.sh milestone 3  (build/test entry point; ./Scripts/test.sh exists and is executable)
[NOT REPLAYED] ./Scripts/test.sh milestone 4  (build/test entry point; ./Scripts/test.sh exists and is executable)

=== ALL 25 README EXAMPLE COMMANDS PASSED (README.md + README.zh-CN.md) ===
