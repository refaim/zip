package zip

import (
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

func sanitizeZoneIdentifier(data []byte) []byte {
	utf16 := isUTF16LE(data)
	var content string
	if utf16 {
		content = decodeUTF16LE(data)
	} else {
		content = string(data)
	}

	lines := strings.Split(content, "\n")
	zoneID := "3" // Default to Internet Zone (3) if parsing fails
	found := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ZoneId=") {
			val := strings.TrimPrefix(line, "ZoneId=")
			if len(val) > 0 && val[0] >= '0' && val[0] <= '4' {
				zoneID = string(val[0])
				found = true
			}
		}
	}
	if !found {
		return data
	}

	sanitized := "[ZoneTransfer]\r\nZoneId=" + zoneID + "\r\n"
	if utf16 {
		return encodeUTF16LE(sanitized)
	}
	return []byte(sanitized)
}

func isUTF16LE(data []byte) bool {
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return true
	}
	if len(data) >= 4 && data[1] == 0 && data[3] == 0 {
		return true
	}
	return false
}

func decodeUTF16LE(data []byte) string {
	start := 0
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		start = 2
	}
	var b strings.Builder
	for i := start; i < len(data)-1; i += 2 {
		r := rune(data[i]) | (rune(data[i+1]) << 8)
		b.WriteRune(r)
	}
	return b.String()
}

func encodeUTF16LE(s string) []byte {
	// utf16.Encode splits what does not fit in one code unit into a surrogate
	// pair, so every unit written here is the whole of what it stands for;
	// spelling the units out a byte at a time used to keep the low sixteen
	// bits of the rune and drop the rest.
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 0, 2+2*len(units))
	buf = append(buf, 0xFF, 0xFE)
	for _, u := range units {
		buf = binary.LittleEndian.AppendUint16(buf, u)
	}
	return buf
}
