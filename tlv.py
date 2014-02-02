from scapy.all import *

class TLVError(Exception):
    pass


class TLV:
    def __init__(self, tl_in_l=False, t_ext=0, l_ext=0):
        self.buffer = ""
        self.tl_in_l = tl_in_l
        self.t_ext = t_ext
        self.l_ext = l_ext


    def _int(self, i, ext):
        maxi = 1<<8
        if ext > 0:
            maxi = (1 << ext)
        holdstr = ""
        holder = i
        extend = 0
        count = 1
        while holder >= maxi:
            count += 1
            newnum = (holder & (maxi - 1))
            holdstr = chr(newnum | extend) + holdstr
            extend = maxi
            holder /= maxi

        holdstr = chr(holder | extend) + holdstr
        return holdstr


    def _t(self, t):
        if self.t_ext == 0 and t > 256:
            raise TLVError("type > 256 and no extension bit set")
        return self._int(t, self.t_ext)


    def _l(self, l):
        if self.l_ext == 0 and l > 256:
            raise TLVError("length > 256 and no extension bit set")
        return self._int(l, self.l_ext)


    def add(self, t, v, l=None):
        self.buffer += self._t(t)
        length = 0 if l is None else l

        if self.tl_in_l:
            length += tlen

        if l is None:
            length += len(v)

        self.buffer += self._l(length)
        self.buffer += v


    def __str__(self):
        return self.buffer


    def __repr__(self):
        return self.buffer


class TLVParser:
    def __init__(self, buffer, tl_in_l=False, t_ext=0, l_ext=0):
        self.buffer = buffer
        self.tl_in_l = tl_in_l
        self.t_ext = t_ext
        self.l_ext = l_ext
        self.offset = 0


    def _get_i(self, i_ext):
        try:
            byte = ord(self.buffer[self.offset])
        except IndexError:
            raise TLVError("Not enough data")
        ext = 1 << (i_ext if i_ext > 0 else 8)
        i = 0
        while byte & ext:
            i += (byte & (ext - 1))
            i <<= i_ext
            self.offset += 1
            try:
                byte = ord(self.buffer[self.offset])
            except IndexError:
                raise TLVError("Not enough data")
        i += byte
        self.offset += 1
        return i


    def _get_tlv(self):
        t = self._get_i(self.t_ext)
        l = self._get_i(self.l_ext)
        if self.offset + l > len(self.buffer):
            raise TLVError("Buffer not long enough to encompass TLV")
        v = self.buffer[self.offset:self.offset+l]
        self.offset += l
        return (t, l, v)


    def parse(self):
        while self.offset < len(self.buffer):
            t, l, v = self._get_tlv()
            yield {
                "type": t,
                "length": l,
                "value": v,
            }

# Test/example program for building TLVs and parsing the TLVs
if __name__ == "__main__":
    tlv = TLV(t_ext=7, l_ext=7)
    tlv.add(10, "Foobar")
    tlv.add(16, "Bladibla")
    hexdump(tlv)
    tlvp = TLVParser(tlv.buffer, t_ext=7, l_ext=7)
    for avp in tlvp.parse():
        print ("%d(%d): %s" % (avp["type"], avp["length"], avp["value"]))
