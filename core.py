import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from argparse import Namespace
from typing import Literal

import extract_dtb
import requests
from rich.console import Console
from rich.progress import track

import banner
import contextpatch
import ext4
import fspatch
import imgextractor
import lpunpack
import mkdtboimg
import utils
from api import cat, cls, dir_has, dirsize
from log import *
from utils import JsonEdit, SetUtils, gettype, simg2img, versize

LOCALDIR = os.getcwd()
SETTINGS_PATH = os.path.join(LOCALDIR, "bin", "settings.json")
settings = SetUtils(SETTINGS_PATH)
settings.load_set()


def get_binary_path(bname: str) -> str:
    """
    获取二进制文件的路径
    :param bname: 二进制文件名
    :return: 二进制文件路径
    """
    global LOCALDIR
    BIN_PATH = os.path.join(LOCALDIR, "bin")

    arch_type = platform.machine()
    os_type = platform.system()

    # find binary from here
    SUITABLE_BIN_PATH = os.path.join(BIN_PATH, os_type, arch_type) + os.sep
    return os.path.join(SUITABLE_BIN_PATH, bname)


class Setting:
    def settings1(self):
        actions = {
            "1": lambda: settings.change(
                "brcom",
                (
                    brcom
                    if (
                        brcom := input(
                            f"  调整brotli压缩等级(整数1-9，级别越高，压缩率越大，耗时越长):"
                        )
                    ).isdigit()
                    and 0 < int(brcom) < 10
                    else "1"
                ),
            ),
            "2": lambda: settings.change(
                "diysize",
                "1" if input("  打包Ext镜像大小[1]动态最小 [2]原大小:") == "2" else "",
            ),
            "3": lambda: settings.change(
                "pack_e2",
                (
                    "0"
                    if input("  打包方案: [1]make_ext4fs [2]mke2fs+e2fsdroid:") == "1"
                    else "1"
                ),
            ),
            "6": lambda: settings.change(
                "pack_sparse",
                (
                    "1"
                    if input("  Img是否打包为sparse镜像(压缩体积)[1/0]\n  请输入序号:")
                    == "1"
                    else "0"
                ),
            ),
            "7": lambda: settings.change(
                "diyimgtype",
                "1" if input(f"  打包镜像系统[1]同解包格式 [2]可选择:") == "2" else "",
            ),
            "8": lambda: settings.change(
                "erofs_old_kernel",
                "1" if input(f"  EROFS打包是否支持旧内核[1/0]") == "1" else "0",
            ),
        }
        cls()
        print(
            f"""
        \033[33m  > 打包设置 \033[0m
           1> Brotli 压缩等级 \033[93m[{settings.brcom}]\033[0m\n
           ----[EXT4设置]------
           2> 大小处理 \033[93m[{settings.diysize}]\033[0m
           3> 打包方式 \033[93m[{settings.pack_e2}]\033[0m\n
           ----[EROFS设置]-----
           4> 压缩方式 \033[93m[{settings.erofslim}]\033[0m\n
           ----[IMG设置]-------
           5> UTC时间戳 \033[93m[{settings.utcstamp}]\033[0m
           6> 创建sparse \033[93m[{settings.pack_sparse}]\033[0m
           7> 文件系统 \033[93m[{settings.diyimgtype}]\033[0m
           8> 支持旧内核 \033[93m[{settings.erofs_old_kernel}]\033[0m\n
           0>返回上一级菜单
           --------------------------
        """
        )
        op_pro = input("   请输入编号:")
        if op_pro == "0":
            return
        elif op_pro in actions.keys():
            actions[op_pro]()
        elif op_pro == "4":
            if input("  选择erofs压缩方式[1]是 [2]否:") == "1":
                erofslim = input(
                    "  选择erofs压缩方式：lz4/lz4hc/lzma/和压缩等级[1-9](数字越大耗时更长体积更小) 例如 lz4hc,8:"
                )
                settings.change("erofslim", erofslim if erofslim else "lz4hc,8")
            else:
                settings.change("erofslim", "lz4hc,8")
        elif op_pro == "5":
            if input("  设置打包UTC时间戳[1]自动 [2]自定义:") == "2":
                utcstamp = input("  请输入: ")
                settings.change(
                    "utcstamp", utcstamp if utcstamp.isdigit() else "1717840117"
                )
            else:
                settings.change("utcstamp", "")
        else:
            print("Input error!")
        self.settings1()

    def settings2(self):
        cls()
        actions = {
            "1": lambda: settings.change(
                "super_group",
                (
                    super_group
                    if (super_group := input(f"  请输入（无特殊字符）:"))
                    else "qti_dynamic_partitions"
                ),
            ),
            "2": lambda: settings.change(
                "metadatasize",
                (
                    metadatasize
                    if (
                        metadatasize := input(
                            "  设置metadata最大保留size(默认为65536，至少512):"
                        )
                    )
                    else "65536"
                ),
            ),
            "3": lambda: settings.change(
                "BLOCKSIZE",
                (
                    BLOCKSIZE
                    if (
                        BLOCKSIZE := input(
                            f"  分区打包扇区/块大小：{settings.BLOCKSIZE}\n  请输入: "
                        )
                    )
                    else "4096"
                ),
            ),
            "4": lambda: settings.change(
                "BLOCKSIZE",
                (
                    SBLOCKSIZE
                    if (
                        SBLOCKSIZE := input(
                            f"  分区打包扇区/块大小：{settings.SBLOCKSIZE}\n  请输入: "
                        )
                    )
                    else "4096"
                ),
            ),
            "5": lambda: settings.change(
                "supername",
                (
                    supername
                    if (
                        supername := input(
                            f"  当前动态分区物理分区名(默认super)：{settings.supername}\n  请输入（无特殊字符）: "
                        )
                    )
                    else "super"
                ),
            ),
            "6": lambda: settings.change(
                "fullsuper",
                "" if input("  是否强制创建Super镜像？[1/0]") != "1" else "-F",
            ),
            "7": lambda: settings.change(
                "autoslotsuffixing",
                "" if input("  是否标记需要Slot后缀的分区？[1/0]") != "1" else "-x",
            ),
        }
        print(
            f"""
        \033[33m  > 动态分区设置 \033[0m
           1> Super簇名 \033[93m[{settings.super_group}]\033[0m\n
           ----[Metadata设置]--
           2> 最大保留Size \033[93m[{settings.metadatasize}]\033[0m\n
           ----[分区设置]------
           3> 默认扇区/块大小 \033[93m[{settings.BLOCKSIZE}]\033[0m\n
           ----[Super设置]-----
           4> 指定block大小 \033[93m[{settings.SBLOCKSIZE}]\033[0m
           5> 更改物理分区名 \033[93m[{settings.supername}]\033[0m
           6> 强制生成完整Img \033[93m[{settings.fullsuper}]\033[0m
           7> 标记分区槽后缀 \033[93m[{settings.autoslotsuffixing}]\033[0m\n
           0>返回上一级菜单
           --------------------------
        """
        )
        op_pro = input("   请输入编号: ")
        if op_pro == "0":
            return
        elif op_pro in actions.keys():
            actions[op_pro]()
        else:
            wrap_red("Input error!")
        self.settings2()

    def settings3(self):
        cls()
        print(
            f"""
    \033[33m  > 工具设置 \033[0m\n
       1>联网模式 \033[93m[{settings.online}]\033[0m\n
       2>Contexts修补 \033[93m[{settings.context}]\033[0m\n
       0>返回上级\n
       --------------------------
            """
        )
        op_pro = input("   请输入编号: ")
        if op_pro == "0":
            return
        elif op_pro == "1":
            settings.change("online", "false" if settings.online == "true" else "true")
        elif op_pro == "2":
            settings.change(
                "context", "false" if settings.context == "true" else "true"
            )
        self.settings3()

    @staticmethod
    def settings4():
        cls()
        print(f"\033[31m {banner.banner1} \033[0m")
        print("\033[96m 开源的安卓全版本ROM处理工具\033[0m")
        print("\033[31m---------------------------------\033[0m")
        print(f"\033[93m作者:\033[0m \033[92mColdWindScholar\033[0m")
        print(
            f"\033[93m开源地址:\033[0m \033[91mhttps://github.com/ColdWindScholar/TIK\033[0m"
        )
        print(f"\033[93m软件版本:\033[0m \033[44mAlpha Edition\033[0m")
        print(
            f"\033[93m开源协议:\033[0m \033[68mGNU General Public License v3.0 \033[0m"
        )
        print("\033[31m---------------------------------\033[0m")
        print(f"\033[93m特别鸣谢:\033[0m")
        print("\033[94mAffggh")
        print("Yeliqin666")
        print("YukongA")
        print("\033[0m")
        input("\033[31m---------------------------------\033[0m")

    def __init__(self):
        cls()
        print(
            """
    \033[33m  > 设置 \033[0m
       1>[打包]相关设置\n
       2>[动态分区]相关设置\n
       3>工具设置\n
       4>关于工具\n
       0>返回主页
       --------------------------
    """
        )
        op_pro = input("   请输入编号: ")
        if op_pro == "0":
            return
        try:
            getattr(self, "settings%s" % op_pro)()
            self.__init__()
        except AttributeError as e:
            print(f"Input error!{e}")
            self.__init__()


class Tool:
    """
    Free Android Rom Tool
    """

    def __init__(self):
        self.local_dir = os.getcwd()
        print_yellow(f"TIK根目录：{self.local_dir}")

        # current working project
        self.project_name = ""
        # the absolute path of the project
        self.project_root = ""
        # skip them when recognize projects
        self.WHITELIST = ["bin", "ksu-derviers", "__pycache__"]

    def greet(self):
        print(f'\033[31m {getattr(banner, "banner%s" % settings.banner)} \033[0m')
        print("\033[93;44m Alpha Edition \033[0m")

        if settings.online == "true":
            try:
                content = json.loads(
                    requests.get(
                        "https://v1.jinrishici.com/all.json", timeout=2
                    ).content.decode()
                )
                shiju = content["content"]
                fr = content["origin"]
                another = content["author"]
            except (Exception, BaseException):
                print(f"\033[36m “开源，是一场无问西东的前行”\033[0m\n")
            else:
                print(f"\033[36m “{shiju}”")
                print(f"\033[36m---{another}《{fr}》\033[0m\n")
        else:
            print(f"\033[36m “开源，是一场无问西东的前行”")

    def main(self):
        # change the working directory to the project directory
        os.chdir(self.local_dir)

        # key-value pairs of the projects(number: project_name)
        project_num = 0
        projects = {}

        # clear the screen and show the banner
        cls()
        self.greet()

        print(" >\033[33m 项目列表 \033[0m\n")
        print("\033[31m   [00]  删除项目\033[0m\n\n", "  [0]  新建项目\n")

        # list all of the projects
        for project_dir in os.listdir(self.local_dir):
            # neglect the directories in the whitelist
            if project_dir in self.WHITELIST or project_dir.startswith("."):
                continue
            # make sure it is a directory
            if os.path.isdir(os.path.join(self.local_dir, project_dir)):
                project_num += 1
                print(f"   [{project_num}]  {project_dir}\n")
                projects.update({str(project_num): project_dir})

        print("  --------------------------------------")
        print("\033[33m  [77] 设置  [88] 退出\033[0m\n")

        op_pro = input("  请输入序号：")

        if op_pro == "00":
            # delete the project
            if (
                delete_index := input("  请输入你要删除的项目序号:").strip()
            ) in projects.keys():
                if input(f"  确认删除{projects[delete_index]}？[1/0]") == "1":
                    shutil.rmtree(os.path.join(LOCALDIR, projects[delete_index]))
                else:
                    print_red("取消删除")
            else:
                print_red("  项目不存在！")
                input("任意按钮继续")

        elif op_pro == "0":
            new_project_name = input("请输入项目名称(非中文)：")
            if new_project_name:
                if os.path.exists(os.path.join(self.local_dir, new_project_name)):
                    wrap_red(f"项目已存在！请更换名称")
                    input("任意按钮继续")
                os.makedirs(os.path.join(self.local_dir, new_project_name, "config"))
                os.makedirs(os.path.join(self.local_dir, new_project_name, "TI_out"))
                print_green(f"项目{new_project_name}创建成功！")
            else:
                print_red("  Input error!")
                input("任意按钮继续")

        elif op_pro == "88":
            cls()
            print_green("\n感谢使用TI-KITCHEN5, 再见！")
            sys.exit(0)

        elif op_pro == "77":
            Setting()

        # enter to the working project
        elif op_pro.isdigit():
            if op_pro in projects.keys():
                # initialize the project
                self.project_name = projects.get(op_pro, "")
                self.project_root = os.path.join(self.local_dir, self.project_name)
                self.project()
            else:
                print_red("  Input error!")
                input("任意按钮继续")

        else:
            print_red("  Input error!")
            input("任意按钮继续")

        # back to the main menu
        self.main()

    @staticmethod
    def dis_avb(fstab: str):
        print(f"正在处理: {fstab}")
        if not os.path.exists(fstab):
            return
        with open(fstab, "r") as sf:
            details = sf.read()
        details = re.sub("avb=vbmeta_system,", "", details)
        details = re.sub("avb,", "", details)
        details = re.sub(",avb_keys=.*avbpubkey", "", details)
        with open(fstab, "w") as tf:
            tf.write(details)

    @staticmethod
    def dis_data_encryption(fstab): ...

    def project(self):
        cls()
        # change the working directory
        os.chdir(self.project_root)

        print(" \n\033[31m>项目菜单 \033[0m\n")
        (
            print(f"  项目：{self.project_name}\033[91m(不完整)\033[0m\n")
            if not os.path.exists(os.path.abspath("config"))
            else print(f"  项目：{self.project_name}\n")
        )

        # create the necessary directories if not exists
        os.makedirs(self.project_root + os.sep + "TI_out", exist_ok=True)
        os.makedirs(self.project_root + os.sep + "config", exist_ok=True)

        print("\033[33m    1> 解包菜单     2> 打包菜单\033[0m\n")
        print("\033[33m    3> 定制功能     4> 精简分区\033[0m\n\n")
        print("\033[1;32m    00> 返回主页    88> 退出TIK\033[0m\n")

        op_menu = input("    请输入编号: ")

        if op_menu == "00":
            self.main()
            return

        elif op_menu == "1":
            unpack_choo(self.project_root)

        elif op_menu == "2":
            pack_choo(self.project_root)

        elif op_menu == "3":
            self.custom_rom()

        elif op_menu == "4":
            self.slim_partition()

        elif op_menu == "88":
            cls()
            print_green("\n感谢使用TI-KITCHEN5,再见！")
            sys.exit(0)

        else:
            wrap_red("   Input error!")
            input("任意按钮继续")

        self.project()

    def slim_partition(self):
        print_red("暂未支持")
        input("任意按钮继续")
        pass

    def custom_rom(self):
        cls()
        print(" \033[31m>定制菜单 \033[0m\n")
        print(f"  项目：{self.project_name}\n")
        print("\033[33m    0> 返回上级  1> xxxx\033[0m\n")
        print("\033[33m    2> KSU修补   3> Apatch修补\033[0m\n")
        print("\033[33m    4> 去除avb   5> 去除data加密\033[0m\n")
        op_menu = input("    请输入编号: ")
        if op_menu == "0":
            return
        elif op_menu == "1":
            pass
        elif op_menu == "2":
            self.ksu_patch()
        elif op_menu == "3":
            self.apatch_patch()
        elif op_menu == "4":
            for root, dirs, files in os.walk(LOCALDIR + os.sep + self.project_name):
                for file in files:
                    if file.startswith("fstab."):
                        self.dis_avb(os.path.join(root, file))
        elif op_menu == "5":
            wrap_red("暂未支持")
            ...
        else:
            wrap_red("   Input error!")
        input("任意按钮继续")
        self.custom_rom()

    def ksu_patch(self):
        cls()
        cs = 0
        project = self.local_dir + os.sep + self.project_name
        os.chdir(self.local_dir)
        print(" \n\033[31m>ksu修补 \033[0m\n")
        print(f"  项目：{self.project_name}\n")
        print(f"  请将要修补的镜像放入{project}")

        boots = {}
        for i in os.listdir(project):
            if os.path.isdir(os.path.join(project, i)):
                continue
            if gettype(os.path.join(project, i)) in ["boot", "init_boot"]:
                cs += 1
                boots[str(cs)] = os.path.join(project, i)
                print(f"  [{cs}]--{i}")
        print("\033[33m-------------------------------\033[0m")
        print("\033[33m    [00] 返回\033[0m\n")
        op_menu = input("    请输入需要修补的boot的序号: ")

        if op_menu in boots.keys():
            kmi = {"1": "android13-5.15", "2": "android14-5.15", "3": "android14-6.1"}
            print("\033[33m-------------------------------\033[0m")
            print("\033[33m    [00] 取消修补\033[0m\n")
            for i in kmi.keys():
                print(f"    {i}: {kmi[i]}\n")
            kmi_choice = input("\033[33m请选择内核镜像需要的kmi: \033[0m")

            if kmi_choice == "00":
                return

            os.system(
                rf"{get_binary_path('ksud')} boot-patch \
                    -b {boots[op_menu]} \
                    --magiskboot {get_binary_path('magiskboot')} \
                    --kmi={kmi.get(kmi_choice)} \
                    --out {project}"
            )

        elif op_menu == "00":
            os.chdir(project)
            return
        else:
            wrap_red("Input Error!")
        input("任意按钮继续")
        self.project()

    def apatch_patch(self): ...


def unpack_choo(project_dir:str):
    """解包前端"""
    cls()
    os.chdir(project_dir)
    print(" \033[31m >分解 \033[0m\n")
    filen = 0
    files = {}
    infos = {}
    wrap_red(f"  请将文件放于{project_dir}根目录下！\n")
    print(" [0]- 分解所有文件\n")

    if dir_has(project_dir, ".img"):
        print("\033[33m [Img]文件\033[0m\n")
        for img0 in os.listdir(project_dir):
            if img0.endswith(".img"):
                if os.path.isfile(os.path.abspath(img0)):
                    filen += 1
                    info = gettype(os.path.abspath(img0))
                    (
                        wrap_red(f"   [{filen}]- {img0} <UNKNOWN>\n")
                        if info == "unknow"
                        else print(f"   [{filen}]- {img0} <{info.upper()}>\n")
                    )
                    files[filen] = img0
                    infos[filen] = "img" if info != "sparse" else "sparse"

    if dir_has(project_dir, ".dtb"):
        print("\033[33m [Dtb]文件\033[0m\n")
        for dtb0 in os.listdir(project_dir):
            if dtb0.endswith(".dtb"):
                if (
                    os.path.isfile(os.path.abspath(dtb0))
                    and gettype(os.path.abspath(dtb0)) == "dtb"
                ):
                    filen += 1
                    print(f"   [{filen}]- {dtb0}\n")
                    files[filen] = dtb0
                    infos[filen] = "dtb"

    print("\n\033[33m  [00] 返回  [77] 循环解包  \033[0m")
    print("  --------------------------------------")
    filed = input("  请输入对应序号：")

    if filed == "0":
        for v in files.keys():
            unpack(files[v], infos[v], project_dir)

    elif filed == "77":
        imgcheck = 0
        upacall = input("  是否解包所有文件？ [1/0]")
        for v in files.keys():
            if upacall != "1":
                imgcheck = input(f"  是否解包{files[v]}?[1/0]")
            if upacall == "1" or imgcheck != "0":
                unpack(files[v], infos[v], project_dir)

    elif filed == "00":
        return

    elif filed.isdigit():
        (
            unpack(files[int(filed)], infos[int(filed)], project_dir)
            if int(filed) in files.keys()
            else wrap_red("Input error!")
        )

    else:
        wrap_red("Input error!")

    input("任意按钮继续")
    unpack_choo(project_dir)


def pack_choo(project_dir: str):
    """打包前端"""
    cls()
    print(" \033[31m >打包 \033[0m\n")
    partn = 0
    parts = {}
    types = {}
    json_ = JsonEdit(project_dir + os.sep + "config" + os.sep + "parts_info").read()
    if not os.path.exists(project_dir + os.sep + "config"):
        os.makedirs(project_dir + os.sep + "config")
    if project_dir:
        print("   [0]- 打包所有镜像\n")
        for packs in os.listdir(project_dir):
            if os.path.isdir(project_dir + os.sep + packs):
                if os.path.exists(
                    project_dir + os.sep + "config" + os.sep + packs + "_fs_config"
                ):
                    partn += 1
                    parts[partn] = packs
                    if packs in json_.keys():
                        typeo = json_[packs]
                    else:
                        typeo = "ext"
                    types[partn] = typeo
                    print(f"   [{partn}]- {packs} <{typeo}>\n")
                elif os.path.exists(project_dir + os.sep + packs + os.sep + "comp"):
                    partn += 1
                    parts[partn] = packs
                    types[partn] = "bootimg"
                    print(f"   [{partn}]- {packs} <bootimg>\n")
                elif os.path.exists(
                    project_dir + os.sep + "config" + os.sep + "dtbinfo_" + packs
                ):
                    partn += 1
                    parts[partn] = packs
                    types[partn] = "dtb"
                    print(f"   [{partn}]- {packs} <dtb>\n")
                elif os.path.exists(
                    project_dir + os.sep + "config" + os.sep + "dtboinfo_" + packs
                ):
                    partn += 1
                    parts[partn] = packs
                    types[partn] = "dtbo"
                    print(f"   [{partn}]- {packs} <dtbo>\n")

        print("\n\033[33m [66] 打包Super [00]返回\033[0m")
        print("  --------------------------------------")
        filed = input("  请输入对应序号：")
        # default
        form = "img"
        # default is raw
        israw = True

        # pack all images
        if filed == "0":
            print_yellow("您的选择是：打包所有镜像")
            op_menu = input("  输出文件格式[1]raw [2]sparse:")
            if op_menu == "2":
                israw = False
            imgtype = input("  手动打包所有分区格式为：[1]ext4 [2]erofs [3]f2fs:")
            if imgtype == "1":
                imgtype = "ext"
            elif imgtype == "2":
                imgtype = "erofs"
            else:
                imgtype = "f2fs"

            for f in track(parts.keys()):
                print_yellow(f"打包{parts[f]}...")
                if types[f] == "bootimg":
                    dboot(
                        project_dir + os.sep + parts[f],
                        project_dir + os.sep + parts[f] + ".img",
                    )
                elif types[f] == "dtb":
                    makedtb(parts[f], project_dir)
                elif types[f] == "dtbo":
                    makedtbo(parts[f], project_dir)
                else:
                    pack_img(project_dir, parts[f], imgtype, israw)
        elif filed == "66":
            packsuper(project_dir)
        elif filed == "00":
            return
        elif filed.isdigit():
            if int(filed) in parts.keys():
                if types[int(filed)] not in [
                    "bootimg",
                    "dtb",
                    "dtbo",
                ]:
                    imgtype = input(
                        "  手动打包所有分区格式为：[1]ext4 [2]erofs [3]f2fs:"
                    )
                    if imgtype == "1":
                        imgtype = "ext"
                    elif imgtype == "2":
                        imgtype = "erofs"
                    else:
                        imgtype = "f2fs"

                    if input("  输出文件格式[1]raw [2]sparse:") == "2":
                        israw = False

                print_yellow(f"打包{parts[int(filed)]}")
                if types[int(filed)] == "bootimg":
                    dboot(
                        project_dir + os.sep + parts[int(filed)],
                        project_dir + os.sep + parts[int(filed)] + ".img",
                    )
                elif types[int(filed)] == "dtb":
                    makedtb(parts[int(filed)], project_dir)
                elif types[int(filed)] == "dtbo":
                    makedtbo(parts[int(filed)], project_dir)
                else:
                    pack_img(project_dir, parts[int(filed)], imgtype, israw, json_)
            else:
                wrap_red("Input error!")
        else:
            wrap_red("Input error!")
        input("任意按钮继续")
        pack_choo(project_dir)


def dboot(infile, orig):
    flag = ""
    if not os.path.exists(infile):
        print(f"Cannot Find {infile}...")
        return
    if os.path.isdir(infile + os.sep + "ramdisk"):
        try:
            os.chdir(infile + os.sep + "ramdisk")
        except Exception as e:
            print("Ramdisk Not Found.. %s" % e)
            return

        os.system(
            'busybox ash -c "find | sed 1d | %s -H newc -R 0:0 -o -F ../ramdisk-new.cpio"'
            % {get_binary_path("cpio")},
        )
        os.chdir(infile)
        with open("comp", "r", encoding="utf-8") as compf:
            comp = compf.read()
        print("Compressing:%s" % comp)
        if comp != "unknow":
            if os.system("magiskboot compress=%s ramdisk-new.cpio" % comp) != 0:
                print("Pack Ramdisk Fail...")
                os.remove("ramdisk-new.cpio")
                return
            else:
                print("Pack Ramdisk Successful..")
                try:
                    os.remove("ramdisk.cpio")
                except (Exception, BaseException):
                    ...
                os.rename("ramdisk-new.cpio.%s" % comp.split("_")[0], "ramdisk.cpio")
        else:
            print("Pack Ramdisk Successful..")
            os.remove("ramdisk.cpio")
            os.rename("ramdisk-new.cpio", "ramdisk.cpio")
        if comp == "cpio":
            flag = "-n"
    else:
        os.chdir(infile)
    if os.system("magiskboot repack %s %s" % (flag, orig)) != 0:
        print("Pack boot Fail...")
        return
    else:
        os.remove(orig)
        os.rename(infile + os.sep + "new-boot.img", orig)
        os.chdir(LOCALDIR)
        try:
            shutil.rmtree(infile)
        except (Exception, BaseException):
            print("删除错误...")
        print("Pack Successful...")


def unpackboot(file, project):
    name = os.path.basename(file).replace(".img", "")
    shutil.rmtree(project + os.sep + name)
    os.makedirs(project + os.sep + name)
    os.chdir(project + os.sep + name)
    if os.system("magiskboot unpack -h %s" % file) != 0:
        print("Unpack %s Fail..." % file)
        os.chdir(LOCALDIR)
        shutil.rmtree(project + os.sep + name)
        return
    if os.access(project + os.sep + name + os.sep + "ramdisk.cpio", os.F_OK):
        comp = gettype(project + os.sep + name + os.sep + "ramdisk.cpio")
        print(f"Ramdisk is {comp}")
        with open(project + os.sep + name + os.sep + "comp", "w") as f:
            f.write(comp)
        if comp != "unknow":
            os.rename(
                project + os.sep + name + os.sep + "ramdisk.cpio",
                project + os.sep + name + os.sep + "ramdisk.cpio.comp",
            )
            if (
                os.system(
                    "magiskboot decompress %s %s"
                    % (
                        project + os.sep + name + os.sep + "ramdisk.cpio.comp",
                        project + os.sep + name + os.sep + "ramdisk.cpio",
                    )
                )
                != 0
            ):
                print("Decompress Ramdisk Fail...")
                return
        if not os.path.exists(project + os.sep + name + os.sep + "ramdisk"):
            os.mkdir(project + os.sep + name + os.sep + "ramdisk")
        os.chdir(project + os.sep + name + os.sep)
        print("Unpacking Ramdisk...")
        os.system("cpio -i -d -F ramdisk.cpio -D ramdisk")
        os.chdir(LOCALDIR)
    else:
        print("Unpack Done!")
    os.chdir(LOCALDIR)


def undtb(project, infile):
    dtbdir = project + os.sep + os.path.basename(infile).split(".")[0]
    shutil.rmtree(dtbdir)
    if not os.path.exists(dtbdir):
        os.makedirs(dtbdir)
    extract_dtb.extract_dtb.split(
        Namespace(filename=infile, output_dir=dtbdir + os.sep + "dtb_files", extract=1)
    )
    print_yellow("正在反编译dtb...")
    for i in track(os.listdir(dtbdir + os.sep + "dtb_files")):
        if i.endswith(".dtb"):
            name = i.split(".")[0]
            dtb = os.path.join(dtbdir, "dtb_files", name + ".dtb")
            dts = os.path.join(dtbdir, "dtb_files", name + ".dts")
            os.system(f"dtc -@ -I dtb -O dts {dtb} -o {dts}")
    open(
        project
        + os.sep
        + os.sep
        + "config"
        + os.sep
        + "dtbinfo_"
        + os.path.basename(infile).split(".")[0],
        "w",
    ).close()
    print_green("反编译完成!")


def makedtb(sf, project):
    dtbdir = project + os.sep + sf
    shutil.rmtree(dtbdir + os.sep + "new_dtb_files")
    os.makedirs(dtbdir + os.sep + "new_dtb_files")
    for dts_files in os.listdir(dtbdir + os.sep + "dtb_files"):
        new_dtb_files = dts_files.split(".")[0]
        print_yellow(f"正在回编译{dts_files}为{new_dtb_files}.dtb")
        dtb_ = dtbdir + os.sep + "dtb_files" + os.sep + dts_files
        if (
            os.system(
                f'dtc -@ -I "dts" -O "dtb" "{dtb_}" -o "{dtbdir + os.sep}new_dtb_files{os.sep}{new_dtb_files}.dtb"'
            )
            != 0
        ):
            wrap_red("回编译dtb失败")
    with open(project + os.sep + "TI_out" + os.sep + sf, "wb") as sff:
        for dtb in os.listdir(dtbdir + os.sep + "new_dtb_files"):
            if dtb.endswith(".dtb"):
                with open(os.path.abspath(dtb), "rb") as f:
                    sff.write(f.read())
    print_green("回编译完成！")


def undtbo(project, infile):
    dtbodir = project + os.sep + os.path.basename(infile).split(".")[0]
    open(
        project
        + os.sep
        + "config"
        + os.sep
        + "dtboinfo_"
        + os.path.basename(infile).split(".")[0],
        "w",
    ).close()
    shutil.rmtree(dtbodir)
    if not os.path.exists(dtbodir + os.sep + "dtbo_files"):
        os.makedirs(dtbodir + os.sep + "dtbo_files")
        try:
            os.makedirs(dtbodir + os.sep + "dts_files")
        except (Exception, BaseException):
            ...
    print_yellow("正在解压dtbo.img")
    mkdtboimg.dump_dtbo(infile, dtbodir + os.sep + "dtbo_files" + os.sep + "dtbo")
    for dtbo_files in os.listdir(dtbodir + os.sep + "dtbo_files"):
        if dtbo_files.startswith("dtbo."):
            dts_files = dtbo_files.replace("dtbo", "dts")
            print_yellow(f"正在反编译{dtbo_files}为{dts_files}")
            dtbofiles = dtbodir + os.sep + "dtbo_files" + os.sep + dtbo_files
            command = [
                get_binary_path("dtc"),
                "-@",
                "-I dtb",
                "-O dts",
                dtbofiles,
                f"-o {os.path.join(dtbodir, 'dts_files', dts_files)}",
            ]
            if (
                subprocess.call(
                    " ".join(command),
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                != 0
            ):
                wrap_red(f"反编译{dtbo_files}失败！")
                return
    print_green("完成！")
    shutil.rmtree(dtbodir + os.sep + "dtbo_files")


def makedtbo(sf, project):
    dtbodir = project + os.sep + os.path.basename(sf).split(".")[0]
    if os.path.exists(dtbodir + os.sep + "new_dtbo_files"):
        shutil.rmtree(dtbodir + os.sep + "new_dtbo_files")
    if os.path.exists(project + os.sep + os.path.basename(sf).split(".")[0] + ".img"):
        os.remove(project + os.sep + os.path.basename(sf).split(".")[0] + ".img")
    os.makedirs(dtbodir + os.sep + "new_dtbo_files")
    for dts_files in os.listdir(dtbodir + os.sep + "dts_files"):
        new_dtbo_files = dts_files.replace("dts", "dtbo")
        print_yellow(f"正在回编译{dts_files}为{new_dtbo_files}")
        dtb_ = dtbodir + os.sep + "dts_files" + os.sep + dts_files
        command = [
            get_binary_path("dtc"),
            "-@",
            "-I dts",
            "-O dtb",
            dtb_,
            f"-o {dtbodir + os.sep + 'new_dtbo_files' + os.sep + new_dtbo_files}",
        ]
        subprocess.call(
            " ".join(command),
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    print_yellow("正在生成dtbo.img...")
    list_: list[str] = []
    for b in os.listdir(dtbodir + os.sep + "new_dtbo_files"):
        if b.startswith("dtbo."):
            list_.append(dtbodir + os.sep + "new_dtbo_files" + os.sep + b)
    list_ = sorted(list_, key=lambda x: int(float(x.rsplit(".", 1)[1])))
    try:
        mkdtboimg.create_dtbo(
            project + os.sep + os.path.basename(sf).split(".")[0] + ".img", list_, 4096
        )
    except (Exception, BaseException):
        wrap_red(f"{os.path.basename(sf).split('.')[0]}.img生成失败!")
    else:
        print_green(f"{os.path.basename(sf).split('.')[0]}.img生成完毕!")


def pack_img(
    project_dir: str,
    img_name: str,
    img_type: Literal["ext", "erofs", "f2fs"],
    israw: bool,
    json_=None,
):
    if json_ is None:
        json_ = {}
    print(f"project_dir:{project_dir}")
    file_contexts = (
        project_dir + os.sep + "config" + os.sep + img_name + "_file_contexts"
    )
    fs_config = project_dir + os.sep + "config" + os.sep + img_name + "_fs_config"

    utc = int(time.time()) if not settings.utcstamp else settings.utcstamp
    out_img = project_dir + os.sep + "TI_out" + os.sep + img_name + ".img"

    in_files = project_dir + os.sep + img_name + os.sep

    img_size0 = (
        int(cat(project_dir + os.sep + "config" + os.sep + img_name + "_size.txt"))
        if os.path.exists(
            project_dir + os.sep + "config" + os.sep + img_name + "_size.txt"
        )
        else 0
    )

    img_size1 = dirsize(in_files, 1, 1).rsize_v
    if settings.diysize == "" and img_size0 < img_size1:
        wrap_red("您设置的size过小,将动态调整size!")
        img_size0 = dirsize(
            in_files, 1, 3, project_dir + os.sep + "dynamic_partitions_op_list"
        ).rsize_v

    elif settings.diysize == "":
        img_size0 = dirsize(
            in_files, 1, 3, project_dir + os.sep + "dynamic_partitions_op_list"
        ).rsize_v

    # patch file_contexts and fs_config
    fspatch.main(in_files, fs_config)
    utils.qc(fs_config)

    if os.path.exists(file_contexts):
        contextpatch.main(in_files, file_contexts)
        utils.qc(file_contexts)

    size = img_size0 / int(settings.BLOCKSIZE)
    size = int(size)
    if img_type == "erofs":
        print(
            rf"mkfs.erofs \
                -z{settings.erofslim} \
                -T {utc} \
                --mount-point=/{img_name} \
                --fs-config-file={fs_config} \
                --file-contexts={file_contexts} \
                {out_img} \
                {in_files}"
        )
        os.system(
            rf"{get_binary_path('mkfs.erofs')} \
                -z{settings.erofslim} \
                -T {utc} \
                --mount-point=/{img_name} \
                --fs-config-file={fs_config} \
                --file-contexts={file_contexts} \
                {out_img} \
                {in_files}"
        )
    elif img_type == "f2fs":
        size_f2fs = (54 * 1024 * 1024) + img_size1
        size_f2fs = int(size_f2fs * 1.15) + 1
        with open(out_img, "wb") as f:
            f.truncate(size_f2fs)
        os.system(
            rf"{get_binary_path('mkfs.f2fs')} {out_img} \
                -O extra_attr \
                -O inode_checksum \
                -O sb_checksum \
                -O compression \
                -f"
        )
        os.system(
            rf"{get_binary_path('sload.f2fs')} \
                -f {in_files} \
                -C {fs_config} \
                -s {file_contexts} \
                -t /{img_name} \
                {out_img} \
                -c"
        )
    else:
        if os.path.exists(file_contexts):
            os.system(
                rf"{get_binary_path('mke2fs')} \
                    -O ^has_journal \
                    -L {img_name} \
                    -I 256 \
                    -M /{img_name} \
                    -m 0 \
                    -t ext4 \
                    -b {settings.BLOCKSIZE} \
                    {out_img} \
                    {size}"
            )
            os.system(
                rf"{get_binary_path('e2fsdroid')} -e \
                    -T {utc} \
                    -S {file_contexts} \
                    -C {fs_config} \
                    -a /{img_name} \
                    -f {in_files} \
                    {out_img}"
            )
        else:
            wrap_red("Miss file_contexts")

    if not israw:
        os.system(f"img2simg {out_img} {out_img}.s")
        os.remove(out_img)
        os.rename(out_img + ".s", out_img)


def packsuper(project):
    if os.path.exists(project + os.sep + "TI_out" + os.sep + "super.img"):
        os.remove(project + os.sep + "TI_out" + os.sep + "super.img")
    if not os.path.exists(project + os.sep + "super"):
        os.makedirs(project + os.sep + "super")
    cls()
    wrap_red(f"请将需要打包的分区镜像放置于{project}{os.sep}super中！")
    supertype = input("请输入Super类型：[1]A_only [2]AB [3]V-AB-->")
    if supertype == "3":
        supertype = "VAB"
    elif supertype == "2":
        supertype = "AB"
    else:
        supertype = "A_only"
    isreadonly = input("是否设置为只读分区？[1/0]")
    ifsparse = input("是否打包为sparse镜像？[1/0]")
    if not os.listdir(project + os.sep + "super"):
        print("您似乎没有要打包的分区，要移动下列分区打包吗：")
        move_list = []
        for i in os.listdir(project + os.sep + "TI_out"):
            if os.path.isfile(os.path.join(project + os.sep + "TI_out", i)):
                if gettype(os.path.join(project + os.sep + "TI_out", i)) in [
                    "ext",
                    "erofs",
                ]:
                    if i.startswith("dsp"):
                        continue
                    move_list.append(i)
        print("\n".join(move_list))
        if input("确定操作吗[Y/N]") in ["Y", "y", "1"]:
            for i in move_list:
                shutil.move(
                    os.path.join(project + os.sep + "TI_out", i),
                    os.path.join(project + os.sep + "super", i),
                )
    tool_auto_size = (
        sum(
            [
                os.path.getsize(os.path.join(project + os.sep + "super", p))
                for p in os.listdir(project + os.sep + "super")
                if os.path.isfile(os.path.join(project + os.sep + "super", p))
            ]
        )
        + 409600
    )
    tool_auto_size = versize(tool_auto_size)
    checkssize = input(
        f"请设置Super.img大小:[1]9126805504 [2]10200547328 [3]16106127360 [4]工具推荐：{tool_auto_size} [5]自定义"
    )
    if checkssize == "1":
        supersize = 9126805504
    elif checkssize == "2":
        supersize = 10200547328
    elif checkssize == "3":
        supersize = 16106127360
    elif checkssize == "4":
        supersize = tool_auto_size
    else:
        supersize = input("请输入super分区大小（字节数）:")
    print_yellow("打包到TI_out/super.img...")
    insuper(
        project + os.sep + "super",
        project + os.sep + "TI_out" + os.sep + "super.img",
        supersize,
        supertype,
        ifsparse,
        isreadonly,
    )


def insuper(imgdir, outputimg, ssize, stype, sparsev, isreadonly):
    attr = "readonly" if isreadonly == "1" else "none"
    group_size_a = 0
    group_size_b = 0
    for root, dirs, files in os.walk(imgdir):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path) and os.path.getsize(file_path) == 0:
                os.remove(file_path)
    superpa = (
        f"--metadata-size {settings.metadatasize} --super-name {settings.supername} "
    )
    if sparsev == "1":
        superpa += "--sparse "
    if stype == "VAB":
        superpa += "--virtual-ab "
    superpa += f"-block-size={settings.SBLOCKSIZE} "
    for imag in os.listdir(imgdir):
        if imag.endswith(".img"):
            image = imag.replace("_a.img", "").replace("_b.img", "").replace(".img", "")
            if (
                f"partition {image}:{attr}" not in superpa
                and f"partition {image}_a:{attr}" not in superpa
            ):
                if stype in ["VAB", "AB"]:
                    if os.path.isfile(
                        imgdir + os.sep + image + "_a.img"
                    ) and os.path.isfile(imgdir + os.sep + image + "_b.img"):
                        img_sizea = os.path.getsize(imgdir + os.sep + image + "_a.img")
                        img_sizeb = os.path.getsize(imgdir + os.sep + image + "_b.img")
                        group_size_a += img_sizea
                        group_size_b += img_sizeb
                        superpa += f"--partition {image}_a:{attr}:{img_sizea}:{settings.super_group}_a --image {image}_a={imgdir}{os.sep}{image}_a.img --partition {image}_b:{attr}:{img_sizeb}:{settings.super_group}_b --image {image}_b={imgdir}{os.sep}{image}_b.img "
                    else:
                        if not os.path.exists(
                            imgdir + os.sep + image + ".img"
                        ) and os.path.exists(imgdir + os.sep + image + "_a.img"):
                            os.rename(
                                imgdir + os.sep + image + "_a.img",
                                imgdir + os.sep + image + ".img",
                            )

                        img_size = os.path.getsize(imgdir + os.sep + image + ".img")
                        group_size_a += img_size
                        group_size_b += img_size
                        superpa += f"--partition {image}_a:{attr}:{img_size}:{settings.super_group}_a --image {image}_a={imgdir}{os.sep}{image}.img --partition {image}_b:{attr}:0:{settings.super_group}_b "
                else:
                    if not os.path.exists(
                        imgdir + os.sep + image + ".img"
                    ) and os.path.exists(imgdir + os.sep + image + "_a.img"):
                        os.rename(
                            imgdir + os.sep + image + "_a.img",
                            imgdir + os.sep + image + ".img",
                        )

                    img_size = os.path.getsize(imgdir + os.sep + image + ".img")
                    superpa += f"--partition {image}:{attr}:{img_size}:{settings.super_group} --image {image}={imgdir}{os.sep}{image}.img "
                    group_size_a += img_size
                print(f"已添加分区:{image}")
    supersize = ssize
    if not supersize:
        supersize = group_size_a + 4096000
    superpa += f"--device super:{supersize} "
    if stype in ["VAB", "AB"]:
        superpa += "--metadata-slots 3 "
        superpa += f" --group {settings.super_group}_a:{supersize} "
        superpa += f" --group {settings.super_group}_b:{supersize} "
    else:
        superpa += "--metadata-slots 2 "
        superpa += f" --group {settings.super_group}:{supersize} "
    superpa += f"{settings.fullsuper} {settings.autoslotsuffixing} --output {outputimg}"
    (
        wrap_red("创建super.img失败！")
        if os.system(f"lpmake {superpa}") != 0
        else print_green("成功创建super.img!")
    )


def unpack(file, info, project):
    if not os.path.exists(file):
        file = os.path.join(project, file)

    json_ = JsonEdit(os.path.join(project, "config", "parts_info"))
    parts = json_.read()
    if not os.path.exists(project + os.sep + "config"):
        os.makedirs(project + os.sep + "config")
    print_yellow(f"[{info}]解包{os.path.basename(file)}中...")
    if info == "sparse":
        simg2img(os.path.join(project, file))
        unpack(file, gettype(file), project)
    elif info == "dtbo":
        undtbo(project, os.path.abspath(file))
    elif info == "dtb":
        undtb(project, os.path.abspath(file))
    elif info == "img":
        parts[os.path.basename(file).split(".")[0]] = gettype(file)
        unpack(file, gettype(file), project)
    elif info == "ext":
        with open(file, "rb+") as e:
            mount = ext4.Volume(e).get_mount_point
            if mount[:1] == "/":
                mount = mount[1:]
            if "/" in mount:
                mount = mount.split("/")
                mount = mount[len(mount) - 1]
            if mount and os.path.basename(file).split(".")[0] != "mi_ext":
                parts[mount] = "ext"
        with Console().status(f"[yellow]正在提取{os.path.basename(file)}[/]"):
            imgextractor.Extractor().main(
                file, project + os.sep + os.path.basename(file).split(".")[0], project
            )
        try:
            os.remove(file)
        except (Exception, BaseException):
            ...
    elif info == "erofs":
        os.system(
            f"{get_binary_path('extract.erofs')} -i {os.path.abspath(file)} -o {project} -x"
        )
    elif info == "f2fs" and os.name == "posix":
        os.system(
            f"{get_binary_path('extract.f2fs')} -o {project} {os.path.abspath(file)}"
        )
    elif info == "super":
        lpunpack.unpack(os.path.abspath(file), project)
        for v in os.listdir(project):
            if os.path.isfile(project + os.sep + v):
                if os.path.getsize(project + os.sep + v) == 0:
                    os.remove(project + os.sep + v)
                else:
                    if os.path.exists(
                        project + os.sep + v.replace("_a", "")
                    ) or os.path.exists(project + os.sep + v.replace("_b", "")):
                        continue
                    if v.endswith("_a.img"):
                        shutil.move(
                            project + os.sep + v, project + os.sep + v.replace("_a", "")
                        )
                    elif v.endswith("_b.img"):
                        shutil.move(
                            project + os.sep + v, project + os.sep + v.replace("_b", "")
                        )
    elif info in ["boot", "vendor_boot"]:
        unpackboot(os.path.abspath(file), project)
    else:
        wrap_red("未知格式！")
    json_.write(parts)
