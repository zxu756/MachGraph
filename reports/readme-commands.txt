=== MachGraph README Commands Replay (EN + ZH) ===
Date (UTC): 2026-11-13T23:50:10Z
macOS:      macOS 27.0.1 (26A434) arm64

[PASS] Parity check: 16 verbatim CLI commands match between README.md and README.zh-CN.md
$ .build/debug/MachGraph info /bin/ls
  -> OK (ls, 5 segments, 11 sections)
$ .build/debug/MachGraph info /bin/ls --json
  -> OK (JSON fileName=ls, isDemo=false)
$ .build/debug/MachGraph segments /bin/ls
  -> OK (__TEXT .. __LINKEDIT)
$ .build/debug/MachGraph fixups /bin/ls --json
  -> OK (fixups JSON parsed)
$ .build/debug/MachGraph symbols /bin/ls
  -> OK (symtab & [inferred:...] separated)
$ .build/debug/MachGraph codesign /bin/ls
  -> OK (Signed=true Identifier=com.apple.ls)
$ .build/debug/MachGraph disasm /bin/ls --symbol entry --count 12
  -> OK (12 ARM64e instructions decoded from /bin/ls entry)
$ .build/debug/MachGraph disasm Fixtures/demo_arm64_sample --address 0x100000460 --count 10
  -> OK (10 ARM64 instructions decoded at 0x100000460)
$ cp Fixtures/demo_arm64_sample /tmp/machgraph_readme_sample && .build/debug/MachGraph patch-asm ...
  -> OK (16 bytes assembled, valid=true, codesign --verify --strict passed)
$ .build/debug/MachGraph export-html /bin/ls --output /tmp/machgraph_ls_triage.html
  -> OK (standalone bilingual HTML triage report generated)
$ .build/debug/MachGraph --help --lang zh
  -> OK (Simplified Chinese --help verified)
$ .build/debug/MachGraph info --demo --lang zh
  -> OK (explicit --demo emits [演示数据] banner)
$ printf '{...mach_inspect_binary /bin/ls...}' | .build/debug/MachGraph mcp
  -> OK (MCP mach_inspect_binary returned real /bin/ls payload with isError=false)

=== ALL README COMMANDS PASSED (EN + ZH) ===
