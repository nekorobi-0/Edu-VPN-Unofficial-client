package desktop

import "unsafe"

// Compile-time checks for the Win32 ABI on both supported 64-bit architectures.
var _ [976 - unsafe.Sizeof(iconData{})]byte
var _ [unsafe.Sizeof(iconData{}) - 976]byte
var _ [152 - unsafe.Sizeof(openFileName{})]byte
var _ [unsafe.Sizeof(openFileName{}) - 152]byte
var _ [80 - unsafe.Sizeof(windowClass{})]byte
var _ [unsafe.Sizeof(windowClass{}) - 80]byte
var _ [48 - unsafe.Sizeof(winMessage{})]byte
var _ [unsafe.Sizeof(winMessage{}) - 48]byte
