package byteorder

import (
	"encoding/binary"
	"math/bits"
	"net"
	"unsafe"
)

// GetNativeEndian returns the native byte order of the system
func GetNativeEndian() binary.ByteOrder {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		return binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		return binary.BigEndian
	default:
		panic("Could not determine native byte order.")
	}
}

// Uint32ToIP converts a uint32 to IP address from network byte order (big endian)
func Uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

// ToNetwork32 converts a 32-bit integer from host byte order to network byte order (big endian).
func ToNetwork32(n uint32) uint32 {
	if GetNativeEndian() == binary.LittleEndian {
		return bits.ReverseBytes32(n)
	}
	return n
}
