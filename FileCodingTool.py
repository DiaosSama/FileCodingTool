# Author: DiaosSama

import random as rd
from hashlib import md5
import zipfile as zip
import getpass
import sys
import os


class Codingfile:

    def __init__(self, path, filename):
        """
        初始化加密解密类
        :param path: 文件或文件夹所处路径
        :param filename: 文件或文件夹名
        """
        self.path = path
        self.name = filename

    def file_encoding(self, pwd):
        """
        对文件进行加密
        :type pwd: string
        """
        with open(self.path+"\\"+self.name, 'rb') as f:
            text = f.read()
        head = create_md5(pwd, create_salt(pwd))
        with open(self.path+"\\encode-"+self.name, 'wb') as w:
            w.write(bytearray(head+"\n", encoding="utf-8"))
            w.write(self.caesar_encoding(text, pwd))

        print()
        print("Your file {0} has already been encoded as {1}"
              .format(self.name, "encode-"+self.name))
        print()
        f.close()
        w.close()

    def directory_encoding(self, pwd):
        """
        对文件夹进行加密
        :param pwd: 密钥
        """
        path = self.path+"\\"+self.name
        make_zip(path, path+".directory")
        self.name = self.name+".directory"
        self.file_encoding(pwd)
        os.remove(path+".directory")

    def file_decoding(self, pwd):
        """
        对文件进行解密
        :type pwd: string
        """
        with open(self.path+"\\"+self.name, 'rb') as f:
            f.readline()
            text = f.read()
        with open(self.path+"\\decode-"+self.name, 'wb') as w:
            w.write(self.caesar_decoding(text, pwd))

        print()
        print("Your file {0} has already been decoded as {1}"
              .format(self.name, "decode-" + self.name))
        print()
        f.close()
        w.close()

    def directory_decoding(self, pwd):
        """
        对文件夹进行解密
        :param pwd: 密钥
        """
        self.file_decoding(pwd)
        zip_path = self.path + "\\decode-" + self.name
        unmake_zip(zip_path)
        os.remove(zip_path)

    def read_hash(self):
        """
        获取加密文件头的哈希值
        :rtype: string
        """
        with open(self.path+"\\"+self.name, 'rb') as w:
            first = w.readline()
        first = first.decode(encoding="utf-8").strip("\n")
        return first

    @staticmethod
    def caesar_encoding(text, pwd):
        """
        变种凯撒加密
        :type pwd: string
        :type text: bytes
        :rtype: bytearray
        """
        text = bytearray(text)
        pwd = bytes(pwd, encoding="utf-8")
        offset = []

        for i in range(len(pwd)):
            offset.append(pwd[i])
        offset = traversal(offset)    # 生成一个将秘钥无限循环的生成器

        for i in range(len(text)):
            text[i] = (text[i]+next(offset)) % 256
        return text

    @staticmethod
    def caesar_decoding(text, pwd):
        """
        变种凯撒解密
        :type text: bytes
        :type pwd: string
        :rtype: bytearray
        """
        text = bytearray(text)
        pwd = bytes(pwd, encoding="utf-8")
        offset = []

        for i in range(len(pwd)):
            offset.append(pwd[i])
        offset = traversal(offset)

        for i in range(len(text)):
            byte = text[i] - next(offset)
            if byte < 0:
                text[i] = byte + 256
            else:
                text[i] = byte
        return text

    def check_key(self, pwd):
        """
        判断密钥是否正确
        :type pwd: string
        :rtype: bool
        """
        pwdhash = create_md5(pwd, create_salt(pwd))
        if pwdhash == self.read_hash():
            return True
        else:
            return False


def make_zip(source_dir, zip_path):
    """
    将文件夹打包成zip文件
    :param source_dir: 需要打包的文件夹的路径
    :param zip_path: 生成zip文件的全路径
    """
    zipf = zip.ZipFile(zip_path, 'w')
    pre_len = len(os.path.dirname(source_dir))
    for parent, dirnames, filenames in os.walk(source_dir):
        for filename in filenames:
            pathfile = os.path.join(parent, filename)
            arcname = pathfile[pre_len:].strip(os.path.sep)    #获得相对路径
            zipf.write(pathfile, arcname)
    zipf.close()


def unmake_zip(zip_path):
    """
    解压zip文件
    :param zip_path: zip文件的完整路径
    """
    path = os.path.dirname(zip_path)
    zipf = zip.ZipFile(zip_path, 'r')
    for file in zipf.namelist():
        zipf.extract(file, path)


def create_salt(pwd):
    """
    根据密钥生成随机盐
    :type pwd: string, 密钥
    :rtype: string
    """
    salt = ''
    chars = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./" \
            "~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?"
    rd.seed(pwd)                             # 使用密码作为种子，保证salt可以复现
    for i in range(16):                      # 生成16位的salt
        num = rd.randint(0, len(chars)-1)
        salt += chars[num]
    return salt


def create_md5(pwd, salt):
    """
    将密钥和盐组合并进行md5散列
    :type pwd: string, 密码
    :type salt: string, 盐
    :rtype: string
    """
    m = md5()
    m.update((pwd+salt).encode("UTF-8"))
    return m.hexdigest()                    # 返回十六进制的哈希值


def traversal(list):
    """
    返回一个无限循环的生成器
    :type list: list
    :rtype: generation
    """
    i = 0
    while True:
        length = len(list)
        i = i % length
        yield list[i]
        i += 1


def enter_pwd():
    """
    实现密钥的重复确认，防止用户误操作
    :return: 密钥
    """
    while True:
        print()
        pwd = getpass.getpass("Please enter your password: ")
        cofpwd = getpass.getpass("Please confirm your password: ")
        print()
        if pwd == cofpwd:
            break
        else:
            print("The passwords entered twice are different.")
    return pwd


def main():
    if len(sys.argv) != 4:
        print()
        print("Usage : ")
        print("        python {} [function] [path] [Filename/Directory]".format(sys.argv[0]))
        print("Function : ")
        print("        1. encode")
        print("        2. decode")
        print("Example : ")
        print("        python {} encode E:\ filename.txt".format(sys.argv[0]))
        print("Output : ")
        print("        If you choose encode, you will get a file named 'encode-filename.txt'")
        print("        If you choose decode, you will get a file named 'decode-filename.txt'")
        print("Tips : ")
        print("        If you encode directory, you will get a file named '[Directoryname].directory'")
        print()
        exit(1)

    # 判断文件或文件夹是否存在
    if not os.path.exists(sys.argv[2] + "\\" + sys.argv[3]):
        print()
        print("File or Directory does not exist!")
        print("Path example: " + os.getcwd())
        print()
        exit(1)

    # 判断功能选择
    if sys.argv[1] == "encode":
        file = Codingfile(sys.argv[2], sys.argv[3])
        pwd = enter_pwd()
        if os.path.isdir(os.path.join(sys.argv[2], sys.argv[3])):
            file.directory_encoding(pwd)
        else:
            file.file_encoding(pwd)
        exit(0)

    if sys.argv[1] == "decode":
        file = Codingfile(sys.argv[2], sys.argv[3])
        pwd = enter_pwd()
        if file.check_key(pwd):
            if str(sys.argv[3]).endswith(".directory"):
                file.directory_decoding(pwd)
            else:
                file.file_decoding(pwd)
            exit(0)
        else:
            print()
            print("Wrong Key!")
            print()
            exit(1)


if __name__ == "__main__":
    main()

