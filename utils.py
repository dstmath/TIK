from __future__ import print_function

import errno
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
from os.path import exists
from random import randint, choice
from shutil import move, rmtree
from threading import Thread

import zstandard

import blockimgdiff
import sparse_img
from os import getcwd
import platform as plat
import update_metadata_pb2 as um
from lpunpack import SparseImage


def u64(x):
    return struct.unpack(">Q", x)[0]


DataImage = blockimgdiff.DataImage
# -----
# ====================================================
#          FUNCTION: sdat2img img2sdat
#       AUTHORS: xpirt - luxi78 - howellzhu
#          DATE: 2018-10-27 10:33:21 CEST | 2018-05-25 12:19:12 CEST
# ====================================================
# -----
# ----VALUES
try:
    sys.set_int_max_str_digits(0)
except AttributeError:
    pass
elocal = getcwd()
platform = plat.machine()
ostype = plat.system()
binner = elocal + os.sep + "bin"
ebinner = binner + os.sep + ostype + os.sep + platform + os.sep


def call(exe, kz="Y", out=0, shstate=False, sp=0):
    cmd = f"{ebinner}{exe}" if kz == "Y" else exe
    if os.name != "posix":
        conf = subprocess.CREATE_NO_WINDOW
    else:
        if sp == 0:
            cmd = cmd.split()
        conf = 0
    try:
        ret = subprocess.Popen(
            cmd,
            shell=shstate,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=conf,
        )
        for i in iter(ret.stdout.readline, b""):
            if out == 0:
                print(i.decode("utf-8", "ignore").strip())
    except subprocess.CalledProcessError as e:
        ret = None
        ret.wait = print
        ret.returncode = 1
        for i in iter(e.stdout.readline, b""):
            if out == 0:
                print(i.decode("utf-8", "ignore").strip())
    ret.wait()
    return ret.returncode


dn = None
formats = (
    [b"PK", "zip"],
    [b"OPPOENCRYPT!", "ozip"],
    [b"7z", "7z"],
    [b"\x53\xef", "ext", 1080],
    [b"\x10\x20\xF5\xF2", "f2fs", 1024],
    [b"\x3a\xff\x26\xed", "sparse"],
    [b"\xe2\xe1\xf5\xe0", "erofs", 1024],
    [b"CrAU", "payload"],
    [b"AVB0", "vbmeta"],
    [b"\xd7\xb7\xab\x1e", "dtbo"],
    [b"\xd0\x0d\xfe\xed", "dtb"],
    [b"MZ", "exe"],
    [b".ELF", "elf"],
    [b"ANDROID!", "boot"],
    [b"VNDRBOOT", "vendor_boot"],
    [b"AVBf", "avb_foot"],
    [b"BZh", "bzip2"],
    [b"CHROMEOS", "chrome"],
    [b"\x1f\x8b", "gzip"],
    [b"\x1f\x9e", "gzip"],
    [b"\x02\x21\x4c\x18", "lz4_legacy"],
    [b"\x03\x21\x4c\x18", "lz4"],
    [b"\x04\x22\x4d\x18", "lz4"],
    [b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\x03", "zopfli"],
    [b"\xfd7zXZ", "xz"],
    [b"]\x00\x00\x00\x04\xff\xff\xff\xff\xff\xff\xff\xff", "lzma"],
    [b"\x02!L\x18", "lz4_lg"],
    [b"\x89PNG", "png"],
    [b"LOGO!!!!", "logo"],
    [b"\x28\xb5\x2f\xfd", "zstd"],
)

def gettype(file) -> str:
    if not os.path.exists(file):
        return "fne"

    def compare(header: bytes, number: int = 0) -> int:
        with open(file, "rb") as f:
            f.seek(number)
            return f.read(len(header)) == header

    def is_super(fil) -> any:
        with open(fil, "rb") as file_:
            buf = bytearray(file_.read(4))
            if len(buf) < 4:
                return False
            file_.seek(0, 0)

            while buf[0] == 0x00:
                buf = bytearray(file_.read(1))
            try:
                file_.seek(-1, 1)
            except:
                return False
            buf += bytearray(file_.read(4))
        return buf[1:] == b"\x67\x44\x6c\x61"

    def is_super2(fil) -> any:
        with open(fil, "rb") as file_:
            try:
                file_.seek(4096, 0)
            except:
                return False
            buf = bytearray(file_.read(4))
        return buf == b"\x67\x44\x6c\x61"

    try:
        if is_super(file) or is_super2(file):
            return "super"
    except IndexError:
        pass
    for f_ in formats:
        if len(f_) == 2:
            if compare(f_[0]):
                return f_[1]
        elif len(f_) == 3:
            if compare(f_[0], f_[2]):
                return f_[1]
    return "unknow"


def dynamic_list_reader(path):
    data = {}
    with open(path, "r", encoding="utf-8") as l_f:
        for p in l_f.readlines():
            if p[:1] == "#":
                continue
            tmp = p.strip().split()
            if tmp[0] == "remove_all_groups":
                data.clear()
            elif tmp[0] == "add_group":
                data[tmp[1]] = {}
                data[tmp[1]]["size"] = tmp[2]
                data[tmp[1]]["parts"] = []
            elif tmp[0] == "add":
                data[tmp[2]]["parts"].append(tmp[1])
            else:
                print(f"Skip {tmp}")
    return data


def generate_dynamic_list(dbfz, size, set_, lb, work):
    data = [
        "# Remove all existing dynamic partitions and groups before applying full OTA",
        "remove_all_groups",
    ]
    with open(
        work + "dynamic_partitions_op_list", "w", encoding="utf-8", newline="\n"
    ) as d_list:
        if set_ == 1:
            data.append(f"# Add group {dbfz} with maximum size {size}")
            data.append(f"add_group {dbfz} {size}")
        elif set_ in [2, 3]:
            data.append(f"# Add group {dbfz}_a with maximum size {size}")
            data.append(f"add_group {dbfz}_a {size}")
            data.append(f"# Add group {dbfz}_b with maximum size {size}")
            data.append(f"add_group {dbfz}_b {size}")
        for part in lb:
            if set_ == 1:
                data.append(f"# Add partition {part} to group {dbfz}")
                data.append(f"add {part} {dbfz}")
            elif set_ in [2, 3]:
                data.append(f"# Add partition {part}_a to group {dbfz}_a")
                data.append(f"add {part}_a {dbfz}_a")
                data.append(f"# Add partition {part}_b to group {dbfz}_b")
                data.append(f"add {part}_b {dbfz}_b")
        for part in lb:
            if set_ == 1:
                data.append(
                    f'# Grow partition {part} from 0 to {os.path.getsize(work + part + ".img")}'
                )
                data.append(f'resize {part} {os.path.getsize(work + part + ".img")}')
            elif set_ in [2, 3]:
                data.append(
                    f'# Grow partition {part}_a from 0 to {os.path.getsize(work + part + ".img")}'
                )
                data.append(f'resize {part}_a {os.path.getsize(work + part + ".img")}')
        d_list.writelines([key + "\n" for key in data])
        data.clear()


def v_code(num=6) -> str:
    ret = ""
    for i in range(num):
        num = randint(0, 9)
        # num = chr(random.randint(48,57))#ASCII表示数字
        letter = chr(randint(97, 122))  # 取小写字母
        Letter = chr(randint(65, 90))  # 取大写字母
        s = str(choice([num, letter, Letter]))
        ret += s
    return ret


def qc(file_) -> None:
    if not exists(file_):
        return
    with open(file_, "r+", encoding="utf-8", newline="\n") as f:
        data = f.readlines()
        new_data = sorted(set(data), key=data.index)
        if len(new_data) == len(data):
            print("No need to handle")
            return
        f.seek(0)
        f.truncate()
        f.writelines(new_data)
    del data, new_data


def cz(func, *args):
    Thread(target=func, args=args, daemon=True).start()


def simg2img(path):
    with open(path, "rb") as fd:
        if SparseImage(fd).check():
            print("Sparse image detected.")
            print("Process conversion to non sparse image...")
            unsparse_file = SparseImage(fd).unsparse()
            print("Result:[ok]")
        else:
            print(f"{path} not Sparse.Skip!")
    try:
        if os.path.exists(unsparse_file):
            os.remove(path)
            os.rename(unsparse_file, path)
    except Exception as e:
        print(e)


def img2sdat(input_image, out_dir=".", version=None, prefix="system"):
    print("img2sdat binary - version: %s\n" % 1.7)
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
        """            
        1. Android Lollipop 5.0
        2. Android Lollipop 5.1
        3. Android Marshmallow 6.0
        4. Android Nougat 7.0/7.1/8.0/8.1
        """

    blockimgdiff.BlockImageDiff(
        sparse_img.SparseImage(input_image, tempfile.mkstemp()[1], "0"), None, version
    ).Compute(out_dir + "/" + prefix)


def findfile(file, dir_) -> str:
    for root, dirs, files in os.walk(dir_, topdown=True):
        if file in files:
            if os.name == "nt":
                return (root + os.sep + file).replace("\\", "/")
            else:
                return root + os.sep + file
        else:
            pass


def findfolder(dir__, folder_name):
    for root, dirnames, filenames in os.walk(dir__):
        for dirname in dirnames:
            if dirname == folder_name:
                return os.path.join(root, dirname).replace("\\", "/")
    return None


# ----CLASSES


class vbpatch:
    def __init__(self, file_):
        self.file = file_

    def checkmagic(self):
        if os.access(self.file, os.F_OK):
            magic = b"AVB0"
            with open(self.file, "rb") as f:
                buf = f.read(4)
                return magic == buf
        else:
            print("File dose not exist!")

    def readflag(self):
        if not self.checkmagic():
            return False
        if os.access(self.file, os.F_OK):
            with open(self.file, "rb") as f:
                f.seek(123, 0)
                flag = f.read(1)
                if flag == b"\x00":
                    return 0  # Verify boot and dm-verity is on
                elif flag == b"\x01":
                    return 1  # Verify boot but dm-verity is off
                elif flag == b"\x02":
                    return 2  # All verity is off
                else:
                    return flag
        else:
            print("File does not exist!")

    def patchvb(self, flag):
        if not self.checkmagic():
            return False
        if os.access(self.file, os.F_OK):
            with open(self.file, "rb+") as f:
                f.seek(123, 0)
                f.write(flag)
            print("Done!")
        else:
            print("File not Found")

    def restore(self):
        self.patchvb(b"\x00")

    def disdm(self):
        self.patchvb(b"\x01")

    def disavb(self):
        self.patchvb(b"\x02")


class DUMPCFG:
    blksz = 0x1 << 0xC
    headoff = 0x4000
    magic = b"LOGO!!!!"
    imgnum = 0
    imgblkoffs = []
    imgblkszs = []


class BMPHEAD(object):
    def __init__(
        self, buf: bytes = None
    ):  # Read bytes buf and use this struct to parse
        assert buf is not None, f"buf Should be bytes not {type(buf)}"
        # print(buf)
        self.structstr = "<H6I"
        (
            self.magic,
            self.fsize,
            self.reserved,
            self.hsize,
            self.dib,
            self.width,
            self.height,
        ) = struct.unpack(self.structstr, buf)


class XIAOMI_BLKSTRUCT(object):
    def __init__(self, buf: bytes):
        self.structstr = "2I"
        (
            self.imgoff,
            self.blksz,
        ) = struct.unpack(self.structstr, buf)


class LOGODUMPER(object):
    def __init__(self, img: str, out: str, dir__: str = "pic"):
        self.out = out
        self.img = img
        self.dir = dir__
        self.structstr = "<8s"
        self.cfg = DUMPCFG()
        self.chkimg(img)

    def chkimg(self, img: str):
        assert os.access(img, os.F_OK), f"{img} does not found!"
        with open(img, "rb") as f:
            f.seek(self.cfg.headoff, 0)
            self.magic = struct.unpack(
                self.structstr, f.read(struct.calcsize(self.structstr))
            )[0]
            while True:
                m = XIAOMI_BLKSTRUCT(f.read(8))
                if m.imgoff != 0:
                    self.cfg.imgblkszs.append(m.blksz << 0xC)
                    self.cfg.imgblkoffs.append(m.imgoff << 0xC)
                    self.cfg.imgnum += 1
                else:
                    break
        # print(self.magic)
        assert self.magic == b"LOGO!!!!", "File does not match xiaomi logo magic!"
        print("Xiaomi LOGO!!!! format check pass!")

    def unpack(self):
        with open(self.img, "rb") as f:
            print("Unpack:\n" "BMP\tSize\tWidth\tHeight")
            for i in range(self.cfg.imgnum):
                f.seek(self.cfg.imgblkoffs[i], 0)
                bmph = BMPHEAD(f.read(26))
                f.seek(self.cfg.imgblkoffs[i], 0)
                print("%d\t%d\t%d\t%d" % (i, bmph.fsize, bmph.width, bmph.height))
                with open(os.path.join(self.out, "%d.bmp" % i), "wb") as o:
                    o.write(f.read(bmph.fsize))
            print("\tDone!")

    def repack(self):
        with open(self.out, "wb") as o:
            off = 0x5
            for i in range(self.cfg.imgnum):
                print("Write BMP [%d.bmp] at offset 0x%X" % (i, off << 0xC))
                with open(os.path.join(self.dir, "%d.bmp" % i), "rb") as b:
                    bhead = BMPHEAD(b.read(26))
                    b.seek(0, 0)
                    self.cfg.imgblkszs[i] = (bhead.fsize >> 0xC) + 1
                    self.cfg.imgblkoffs[i] = off

                    o.seek(off << 0xC)
                    o.write(b.read(bhead.fsize))

                    off += self.cfg.imgblkszs[i]
            o.seek(self.cfg.headoff)
            o.write(self.magic)
            for i in range(self.cfg.imgnum):
                o.write(struct.pack("<I", self.cfg.imgblkoffs[i]))
                o.write(struct.pack("<I", self.cfg.imgblkszs[i]))
            print("\tDone!")
