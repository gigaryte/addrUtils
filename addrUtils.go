package addrUtils

import (
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

//IPv6Addr stores the upper and lower halves of an IPv6 address
type IPv6Addr struct {
	NetId  uint64 // upper 64 bits
	HostId uint64 // lower 64 bits
}

//IPv6Network holds the base address of an IPv6 network and the netmask
type IPv6Network struct {
	Addr    IPv6Addr //Network (base) address
	Mask    uint8    //Network mask
	Current IPv6Addr //Address we're currently on if we're using random
	//addresses
}

//Parses and initializes an IPv6Network struct from a string network
func (net *IPv6Network) Init(ipStr string) error {

	s := strings.Split(ipStr, "/")
	if len(s) != 2 {
		return fmt.Errorf("argument must be of the form address/netmask")
	}

	addr, err := ipIntFromString(s[0])
	if err != nil {
		return err
	}

	mask, err := strconv.ParseUint(s[1], 10, 8)
	if err != nil {
		return err
	}

	net.Mask = uint8(mask)

	if net.Mask > 128 {
		return fmt.Errorf("netmask cannot be > 128")
	}

	//Bitwise and the mask bits with the address provided
	if net.Mask < 64 {
		andMask := uint64((math.Pow(2, float64(net.Mask)) - 1)) << (64 - uint64(net.Mask))
		net.Addr.NetId = addr.NetId & andMask
	} else {
		net.Addr.NetId = addr.NetId
	}

	hostBits := net.Mask - 64

	if hostBits < 64 {
		andMask := uint64((math.Pow(2, float64(hostBits)) - 1)) << (64 - uint64(hostBits))
		net.Addr.HostId = addr.HostId & andMask
	} else {
		net.Addr.HostId = addr.HostId
	}

	return nil
}

//net.Randomize chooses a random start address in the network
func (net *IPv6Network) Randomize() error {

	if net.Mask < 64 {
		return fmt.Errorf("Randomize() not supported for networks bigger than /64")
	}

	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	net.Current.NetId = net.Addr.NetId

	randHostId := r1.Uint64()
	hostBits := net.Mask - 64
	fmt.Println("Hostbits: ", hostBits)

	pow := math.Pow(2, float64(hostBits))
	//andMask := uint64((math.Pow(2, float64(hostBits)) - 1)) << (64 - uint64(hostBits))
	fmt.Println("Power", pow)
	andMask := uint64(pow) << (64 - hostBits)

	fmt.Printf("andmask: %064b\n", andMask)
	fmt.Printf("^andmask: %064b\n", ^andMask)

	net.Current.HostId = randHostId & (^andMask)

	return nil
}

//net.Next() gets the next address up from the base address
func (net *IPv6Network) Next(ipStr string) error {
	return nil
}

func ipIntFromString(s string) (*IPv6Addr, error) {
	hextetCount := 8
	retAddr := new(IPv6Addr)

	if s == "" {
		return retAddr, fmt.Errorf("IPv6 address cannot be nil")
	}

	parts := strings.Split(s, ":")

	minPartsLen := 3
	if len(parts) < minPartsLen {
		return retAddr, fmt.Errorf("at least %d parts expected in %s", minPartsLen, s)
	}

	if strings.Contains(parts[len(parts)-1], ".") {
		//Get the v4 embedded part
		v4Addr := parts[len(parts)-1]

		//Split address on the '.'
		v4Slice := strings.Split(v4Addr, ".")

		//Valid v4 will have 4 octets
		if len(v4Slice) != 4 {
			return retAddr, fmt.Errorf("IPv4 embedded address must have 4 octets")
		}

		//Convert each octet into hex, keep running tally
		newPart := ""
		for i := 0; i < 4; i++ {
			n, err := strconv.ParseUint(v4Slice[i], 10, 8)
			if err != nil {
				return retAddr, fmt.Errorf("error parsing IPv4 embedded address")
			}
			newPart += fmt.Sprintf("%02x", n)
		}

		//Remove the last slice elt, and tack the converted hex on
		parts = append(parts[:len(parts)-1], newPart[:4])
		parts = append(parts, newPart[4:])
	}

	//An IPv6 Address can have at most 9 colons
	maxPartsLen := 9
	if len(parts) > maxPartsLen {
		return retAddr, fmt.Errorf("at most %d colons permitted in %s", maxPartsLen-1, s)
	}

	//Find a :: with nothing in between
	skip_idx := -1
	for i := 1; i < (len(parts) - 1); i++ {
		if parts[i] == "" && skip_idx >= 0 {
			return retAddr, fmt.Errorf("at most one :: permitted in %s", s)
		} else if parts[i] == "" {
			skip_idx = i
		}
	}

	var parts_hi, parts_lo, parts_skipped int

	//Found a ::
	if skip_idx >= 0 {
		parts_hi = skip_idx
		parts_lo = len(parts) - skip_idx - 1

		if parts[0] == "" {
			parts_hi--
			if parts_hi > 0 {
				return retAddr, fmt.Errorf("leading ':' only permitted as part of :: in %s", s)
			}
		}
		if parts[len(parts)-1] == "" {
			parts_lo--
			if parts_lo > 0 {
				return retAddr, fmt.Errorf("trailing ':' only permitted as part of :: in %s", s)
			}
		}
		parts_skipped = hextetCount - (parts_hi + parts_lo)
		if parts_skipped < 1 {
			return retAddr, fmt.Errorf("expected at most %d other parts with "+
				":: in %s", hextetCount-1, s)
		}
	} else {
		if len(parts) != hextetCount {
			return retAddr, fmt.Errorf("exactly %d parts expected without '::' in %s",
				hextetCount, s)
		}
		if parts[0] == "" {
			return retAddr, fmt.Errorf("leading ':' permitted only as part of"+
				"'::' in %s", s)
		}
		if parts[len(parts)-1] == "" {
			return retAddr, fmt.Errorf("trailing ':' only permitted as part of "+
				"'::' in %s", s)
		}
		parts_hi = len(parts)
		parts_lo = 0
		parts_skipped = 0
	}

	doingHigh := true //keep track of whether we're on high 64 bits or low
	//First stuff high part
	for i := 0; i < parts_hi; i++ {
		val, err := strconv.ParseUint(parts[i], 16, 16)
		if i >= 4 {
			doingHigh = false
		}

		if err != nil {
			return retAddr, err
		}

		if doingHigh {
			retAddr.NetId <<= 16
			retAddr.NetId |= val
		} else {
			retAddr.HostId <<= 16
			retAddr.HostId |= val
		}
	}

	nHextets := parts_hi
	//Now do the skipped stuff
	for i := 0; i < parts_skipped; i++ {

		if (i + nHextets) >= 4 {
			doingHigh = false
		}

		if doingHigh {
			retAddr.NetId <<= 16
		} else {
			retAddr.HostId <<= 16
		}
	}

	nHextets += parts_skipped
	//Finally, do the lo stuff
	for i := 0; i < parts_lo; i++ {
		val, err := strconv.ParseUint(parts[len(parts)-parts_lo+i], 16, 16)

		if err != nil {
			return retAddr, err
		}

		if (i + nHextets) >= 4 {
			doingHigh = false
		}

		if doingHigh {
			retAddr.NetId <<= 16
			retAddr.NetId |= val
		} else {
			retAddr.HostId <<= 16
			retAddr.HostId |= val
		}
	}

	return retAddr, nil
}

func IpToStr(addr *IPv6Addr) string {
	var chunks []string
	fullAddr := fmt.Sprintf("%016x%016x", addr.NetId, addr.HostId)
	runes := []rune(fullAddr)

	for i := 0; i < len(runes); i += 4 {
		nn := i + 4
		if nn > len(runes) {
			nn = len(runes)
		}
		chunks = append(chunks, string(runes[i:nn]))
	}

	return strings.Join(chunks, ":")
}

//Explode returns a full, 8 groups of 4 hex digits representation of a
//(potentially compressed) IPv6 address, (e.g. 2001::1 becomes
//2001:0000:0000:0000:0000:0000:0000:0001). Returns the exploded IPv6 address
//string along with any errors that occurred
func Explode(s string) (string, error) {
	var addr *IPv6Addr
	var err error

	if addr, err = ipIntFromString(s); err != nil {
		return "", fmt.Errorf("ipIntFromString: %s", err)
	}

	return IpToStr(addr), nil
}

//IsEUI64 explodes a string-representation of an IPV6 address (e.g. "2001::1"),
//and checks whether it's EUI-64. It returns the exploded string address and a
//bool that indicates whether the given string is an EUI-64 IPv6 address or not
func IsEUI64(ip string) (string, bool) {

	var exploded string
	var err error
	//Explode the IP so we can check the bit positions
	if exploded, err = Explode(ip); err != nil {
		return "", false
	}

	hextets := strings.Split(exploded, ":")
	sixth := hextets[5]
	seventh := hextets[6]

	if strings.HasSuffix(sixth, "ff") && strings.HasPrefix(seventh, "fe") {
		return exploded, true
	}

	return exploded, false
}

//GetMACFromEUI64 returns a :-separated MAC address from an already-exploded
//EUI-64 IPv6 address
func GetMACFromEUI64(ip string) (string, error) {
	iid := strings.Split(ip, ":")[4:]
	first := iid[0][:2]
	second := iid[0][2:]
	third := iid[1][:2]
	nic := iid[2][2:] + ":" + iid[3][:2] + ":" + iid[3][2:]
	var deloc string
	if firstUint, err := strconv.ParseUint(first, 16, 8); err != nil {
		return "", fmt.Errorf("error parsing first byte of MAC address")
	} else {
		deloc = fmt.Sprintf("%02x", firstUint&0xfd)
	}

	retVal := deloc + ":" + second + ":" + third + ":" + nic
	return retVal, nil
}
