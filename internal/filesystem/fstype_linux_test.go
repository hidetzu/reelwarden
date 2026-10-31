//go:build linux

package filesystem

import "testing"

// On 32-bit Linux statfs f_type is int32: btrfs (0x9123683E) arrives as a
// negative number and must still be recognised.
func TestFSMagicOn32Bit(t *testing.T) {
	for magic, name := range map[uint32]string{0x9123683E: "btrfs", 0xFF534D42: "cifs", 0xEF53: "ext4"} {
		raw := int64(int32(magic)) // what a 32-bit build sees
		fs, ok := fsNames[fsMagic(raw)]
		if !ok || fs.name != name {
			t.Errorf("%#x: got %q, %v; want %s", magic, fs.name, ok, name)
		}
	}
}
