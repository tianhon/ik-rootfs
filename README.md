# iKuai rootfs tools

[![License: WTFPL](https://img.shields.io/badge/License-WTFPL-brightgreen.svg)](./LICENSE)
[![CoC:WTFCoC](https://img.shields.io/badge/CoC-WTFCoC-brightgreen.svg)](./CODE_OF_CONDUCT.md)

ETH(USDT): 0x4568da7585f7d7d980fa30fcd6dd6e151778bbef

TRX(USDT): THYrLLaMpb7zp5ZZXq72XGsgvLqnbdk821

## Chat with us

[![Matrix: Support](https://img.shields.io/badge/Support_&_Feedack-deeppink?style=for-the-badge&label=Matrix+Chat)](https://matrix.to/#/#router-patch:bladerunn.in)

## Usage

```
Usage: build.sh <command> [args...]

Commands:
  unpack <xxx.iso|xxx.bin>
      unpack iso or bin file

  pack_rootfs [firmware_id] [version] [build_time]
      pack rootfs

  pack_bin [firmware_id] [version] [build_time]
      pack bin file

  pack_iso [firmware_id] [version] [build_time]
      pack iso file

  patch <xxx.bin|xxx.iso> <out_type:bin|iso> <patch_dir> [firmware_id] [version] [build_time]
      patch iso or bin file

  clean
      clean work dir

Args:
  Build time:
      Empty : Not change
      0     : Current time
      Number: Use input time

  Firmware id:
      Empty: Not change
      10001: Free Edition
      10002: Enterprise
      Other: Use input id

  Version:
      Empty: Not change
      Other: Use input version

Examples:
  build.sh unpack xxx.iso
  build.sh unpack xxx.bin
  build.sh pack_rootfs
  build.sh pack_bin Id Version 0
  build.sh pack_iso
  build.sh patch xxx.iso patch_dir
  build.sh patch xxx.bin patch_dir 202509221910
```
