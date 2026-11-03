package config

import "testing"

func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		in      int
		want    uint16
		wantErr bool
	}{
		{"default", 4040, 4040, false},
		{"lowest", 1, 1, false},
		{"highest", 65535, 65535, false},
		{"zero", 0, 0, true},
		{"negative", -1, 0, true},
		{"too large", 65536, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidatePort(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePort(%d) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ValidatePort(%d) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateComm(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"normal", "myprocess", false},
		{"long names are allowed (they get truncated)", "averyveryverylongname", false},
		{"empty", "", true},
		{"embedded NUL", "my\x00process", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateComm(tt.in); (err != nil) != tt.wantErr {
				t.Errorf("ValidateComm(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestCommBytes(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string // expected bytes before the NUL padding
	}{
		{"short name", "myprocess", "myprocess"},
		{"single char", "a", "a"},
		{"exactly 15 bytes", "abcdefghijklmno", "abcdefghijklmno"},
		{"16 bytes is cut to 15", "abcdefghijklmnop", "abcdefghijklmno"},
		{"21 bytes is cut to 15", "averyveryverylongname", "averyveryverylo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CommBytes(tt.in)

			// The visible part must match.
			if s := string(got[:len(tt.want)]); s != tt.want {
				t.Errorf("CommBytes(%q) prefix = %q, want %q", tt.in, s, tt.want)
			}
			// Everything after it must be NUL padding, and the final byte is always NUL.
			for i := len(tt.want); i < CommLen; i++ {
				if got[i] != 0 {
					t.Errorf("CommBytes(%q)[%d] = %#x, want 0", tt.in, i, got[i])
				}
			}
			if got[CommLen-1] != 0 {
				t.Errorf("CommBytes(%q) is not NUL terminated", tt.in)
			}
		})
	}
}
