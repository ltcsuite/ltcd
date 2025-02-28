package scrypt

type Hash struct{ Key, Val []byte }

var cache map[string][]byte

func Scrypt(x []byte) []byte {
	if x, ok := cache[string(x)]; ok {
		return x
	}
	return scrypt(x)
}

func SetCache(hashes []Hash) {
	cache = map[string][]byte{}
	for _, hash := range hashes {
		cache[string(hash.Key)] = hash.Val
	}
}
