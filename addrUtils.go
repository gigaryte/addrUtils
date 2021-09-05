package addrUtils

import (
  "fmt"
  "strings"
  "strconv"
)

type IPv6Addr struct {
	netId  uint64 // upper 64 bits
	hostId uint64 // lower 64 bits
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
    return retAddr, fmt.Errorf("At least %d parts expected in %s", minPartsLen, s)
  }

  if strings.Contains(parts[len(parts)-1], "."){
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
        return retAddr, fmt.Errorf("Error parsing IPv4 embedded address")
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
    return retAddr, fmt.Errorf("At most %d colons permitted in %s", maxPartsLen-1, s)
  }

  //Find a :: with nothing in between
  skip_idx := -1
  for i := 1; i < (len(parts) - 1); i++ {
    if parts[i] == "" && skip_idx >= 0 {
        return retAddr, fmt.Errorf("At most one :: permitted in %s", s)
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
        return retAddr, fmt.Errorf("Leading ':' only permitted as part of :: in %s", s)
      }
    }
    if parts[len(parts) - 1] == "" {
      parts_lo--
      if parts_lo > 0 {
        return retAddr, fmt.Errorf("Trailing ':' only permitted as part of :: in %s", s)
      }
    }
    parts_skipped = hextetCount - (parts_hi + parts_lo)
    if parts_skipped < 1 {
      return retAddr, fmt.Errorf("Expected at most %d other parts with :: in %s", 
                                hextetCount - 1, s)
    }
  } else {
    if len(parts) != hextetCount {
      return retAddr, fmt.Errorf("Exactly %d parts expected without '::' in %s", 
                                hextetCount, s)
    }
    if parts[0] == "" {
      return retAddr, fmt.Errorf("Leading ':' permitted only as part of '::' in %s", s)
    }
    if parts[len(parts) - 1] == "" {
      return retAddr, fmt.Errorf("Trailing ':' only permitted as part of '::' in %s", s)
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
      retAddr.netId <<= 16
      retAddr.netId |= val
    } else {
      retAddr.hostId <<= 16
      retAddr.hostId |= val
    }
  }

  nHextets := parts_hi
  //Now do the skipped stuff
  for i := 0; i < parts_skipped; i++ {

    if (i + nHextets) >= 4 {
      doingHigh = false
    }

    if doingHigh {
      retAddr.netId <<= 16
    } else {
      retAddr.hostId <<= 16
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
      retAddr.netId <<= 16
      retAddr.netId |= val
    } else {
      retAddr.hostId <<= 16
      retAddr.hostId |= val
    }
  }

  return retAddr, nil
}

func ipToStr(addr *IPv6Addr) (string) {
    var chunks []string
    fullAddr := fmt.Sprintf("%016x%016x", addr.netId, addr.hostId)
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


func Explode(s string) (string, error){
    var addr *IPv6Addr
    var err error

    if addr, err = ipIntFromString(s); err != nil {
      return "", fmt.Errorf("ipIntFromString: %s\n", err)
    }
    
    return ipToStr(addr), nil
}

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

  return "", false
}

func GetMACFromEUI64(ip string) (string, error) {
  iid := strings.Split(ip, ":")[4:]
  first := iid[0][:2]
  second := iid[0][2:]
  third := iid[1][:2]
  nic := iid[2][2:] + ":" + iid[3][:2] + ":" + iid[3][2:]
  var deloc string
  if firstUint, err := strconv.ParseUint(first, 16, 8); err != nil {
    return "", fmt.Errorf("Error parsing first byte of MAC address")
  } else {
    deloc = fmt.Sprintf("%02x", firstUint & 0xfd)
  }

  retVal := deloc + ":" + second + ":" + third + ":" + nic
  return retVal, nil
}


