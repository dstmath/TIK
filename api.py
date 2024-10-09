import os
import re
import shutil


def cls() -> None:
    """clear the console"""
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("clear")
    else:
        print("Ctrl + L to clear the window")


def dir_has(path: str, endswith: str) -> bool:
    """check if the directory has the file with the specified suffix"""
    for v in os.listdir(path):
        if v.endswith(endswith):
            return True
    return False


def cat(file) -> str:
    """read the content of the file"""
    with open(file, "r") as f:
        return f.read().strip()


def remove_path(path: str) -> None:
    """Remove the file or directory"""
    if os.path.exists(path):
        if os.path.isdir(path):
            shutil.rmtree(path)
        elif os.path.isfile(path):
            os.remove(path)


def recreate_folder(path) -> None:
    """remove the directory and recreate it"""
    remove_path(path)
    if not os.path.exists(path):
        os.makedirs(path)


class dirsize(object):
    """Calculate the size of the directory and adjust the size of the partition
    :param dir: The directory to be calculated
    :param num: The number of partitions
    :param get: The method of partition size calculation
    :param list_f: The file to be modified
    :return: The size of the partition
    """

    # get-command
    # 1 - retun True value of dir size
    # 2 - return Rsize value of dir size
    # 3 - return Rsize value of dir size and modify dynampic_partition_list

    def __init__(self, dir: str, num: int = 1, get: int = 2, list_f: str | None = None):
        self.rsize_v: int
        self.num = num
        self.get = get
        self.list_f = list_f
        self.dname = os.path.basename(dir)
        self.size = 0
        for root, dirs, files in os.walk(dir):
            self.size += sum(
                [
                    os.path.getsize(os.path.join(root, name))
                    for name in files
                    if not os.path.islink(os.path.join(root, name))
                ]
            )
        if self.get == 1:
            self.rsize_v = self.size
        elif self.get in (2, 3):
            self.rsize(self.size, self.num)
        else:
            self.rsize(self.size, self.num)

    def rsize(self, size: int, num: int):
        if size <= 2097152:
            size_ = 2097152
            bs = 1
        else:
            size_ = int(size + 10086)
            if size_ > 2684354560:
                bs = 1.0658
            if size_ <= 2684354560:
                bs = 1.0758
            if size_ <= 1073741824:
                bs = 1.0858
            if size_ <= 536870912:
                bs = 1.0958
            if size_ <= 104857600:
                bs = 1.1158
            else:
                bs = 1.1258
        print(f"Multiple:{bs}")
        if self.list_f:
            self.rsizelist(self.dname, int(size_ * bs), self.list_f)
        self.rsize_v = int(size_ * bs / num)

    @staticmethod
    def rsizelist(dname, size, file):
        if os.access(file, os.F_OK):
            print("调整%s大小为%s" % (dname, size))
            with open(file, "r", encoding="utf-8") as f:
                content = f.read()
            with open(file, "w", encoding="utf-8", newline="\n") as ff:
                content = re.sub(
                    "resize {} \\d+".format(dname),
                    "resize {} {}".format(dname, size),
                    content,
                )
                content = re.sub(
                    "resize {}_a \\d+".format(dname),
                    "resize {}_a {}".format(dname, size),
                    content,
                )
                content = re.sub(
                    "# Grow partition {} from 0 to \\d+".format(dname),
                    "# Grow partition {} from 0 to {}".format(dname, size),
                    content,
                )
                content = re.sub(
                    "# Grow partition {}_a from 0 to \\d+".format(dname),
                    "# Grow partition {}_a from 0 to {}".format(dname, size),
                    content,
                )
                ff.write(content)
