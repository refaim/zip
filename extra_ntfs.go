package zip

import "encoding/binary"

// appendNtfsAcl writes a Windows Security Descriptor to the 0x4453 tag. A
// descriptor too long for the tag's two-byte length is left out rather than
// written under a length that has wrapped: the entry keeps its data and loses
// only the ACL, which is what happens anyway on every reader that does not
// know the tag.
func appendNtfsAcl(extra []byte, sd []byte) []byte {
	if len(sd) == 0 {
		return extra
	}
	sdLen, err := fitUint16(len(sd), "NTFS security descriptor")
	if err != nil {
		return extra
	}
	// Format 0x4453: [ID 2b] [Size 2b] [Data...]
	buf := make([]byte, 4+len(sd))
	binary.LittleEndian.PutUint16(buf[0:2], ntfsAclExtraID)
	binary.LittleEndian.PutUint16(buf[2:4], sdLen)
	copy(buf[4:], sd)
	return append(extra, buf...)
}

// parseNtfsAcl extracts a Security Descriptor
func parseNtfsAcl(extra []byte) []byte {
	for len(extra) >= 4 {
		tag := binary.LittleEndian.Uint16(extra[:2])
		size := binary.LittleEndian.Uint16(extra[2:4])
		extra = extra[4:]
		if int(size) > len(extra) {
			break
		}
		if tag == ntfsAclExtraID {
			sd := make([]byte, size)
			copy(sd, extra[:size])
			return sd
		}
		extra = extra[size:]
	}
	return nil
}
