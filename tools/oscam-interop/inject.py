# Sends one ECM to an OSCam camd35-UDP server (cs357x) so that OSCam forwards it to its TCMG reader.
# usage: inject.py <oscam-user> <port> [provid-hex]   (password of the OSCam user must be "local")
import socket, struct, zlib, hashlib, sys, time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def pkt(user, pwd, srvid, caid, prid, ecm):
    ucrc = struct.pack('>I', zlib.crc32(hashlib.md5(user.encode()).digest()) & 0xffffffff)
    buf = bytearray(20 + len(ecm)); buf[1] = len(ecm)
    struct.pack_into('>H', buf, 8, srvid); struct.pack_into('>H', buf, 10, caid)
    struct.pack_into('>I', buf, 12, prid); struct.pack_into('>H', buf, 16, 1)
    buf[18] = buf[19] = 0xFF; buf[20:] = ecm
    struct.pack_into('>I', buf, 4, zlib.crc32(bytes(ecm)) & 0xffffffff)
    l = (len(buf) + 15) // 16 * 16
    buf += b'\xff' * (l - len(buf))
    enc = Cipher(algorithms.AES(hashlib.md5(pwd.encode()).digest()), modes.ECB()).encryptor()
    return ucrc + enc.update(bytes(buf)) + enc.finalize()
ECM = bytes([0x80,0x00,0x34,0x00,0x32,0x64,0x00,0x7C,0x99,0xBB,0xE9,0x60,0x61,0x74,0x1D,0x82,0xC3,0x57,0x47,0xD5,0x26,0x2E,0x0A,0x0E,
 0x76,0x46,0xAB,0x26,0x35,0x50,0x1A,0xF2,0x63,0xD7,0x26,0x1D,0xC1,0x4F,0x0C,0xF2,0x63,0xD7,0x26,0x1D,0xC1,0x4F,0x0C,0x16,0x88,0x9C,0x7D,0x01,0x21,0x9A,0x20])
user=sys.argv[1]; port=int(sys.argv[2]); prid=int(sys.argv[3],16) if len(sys.argv)>3 else 0
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('127.0.0.2',0)); s.settimeout(8)
s.sendto(pkt(user,'local',0x0064,0x0B00,prid,ECM),('127.0.0.1',port))
try:
    d,_=s.recvfrom(4096)
    enc = Cipher(algorithms.AES(hashlib.md5(b'local').digest()), modes.ECB()).decryptor()
    pl = enc.update(d[4:4+(len(d)-4)//16*16])+enc.finalize()
    print('%s cmd=%02x'%(user,pl[0]),'CW=%s'%(pl[20:36].hex() if pl[0]==1 else 'NONE'))
    sys.exit(0 if pl[0]==1 else 1)
except Exception as e:
    print(user,'no reply',e); sys.exit(2)
