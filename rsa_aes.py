import rsa,binascii
from Crypto.Cipher import AES
from binascii import b2a_hex,a2b_hex
###########RSA加密解密过程
def RSA_en_de():
        source = 'SAIL'
        #第一步，生成公钥，私钥。256的长度
        pub,priv = rsa.newkeys(256)
        # print(pub)
        # print(priv)
        #第二步，使用公钥加密
        encrypt = rsa.encrypt(source.encode(),pub)
        print(encrypt)
        print(binascii.b2a_hex(encrypt).decode())
        #第三步，使用私钥解密（私钥是保留在本机的）
        decrypt = rsa.decrypt(encrypt,priv)
        print(decrypt.decode())
# RSA_en_de()




#########################AES加密解密过程
def AES_en(source='SAIL'):

        # 如果source不足16位的倍数就用\0补足为16位
        if len(source.encode('utf-8')) % 16:
            add = 16 - (len(source.encode('utf-8')) % 16)
        else:
            add = 0
        source = source + ('\0' * add)
        print(source)

        #定义密钥和偏移量，必须是16个字节、24字节或32字节
        key = 'wdawdwadawqw1231'.encode()
        mode = AES.MODE_CBC
        a = b'1231241214121123'
        cryptos = AES.new(key,mode,a)
        #进行加密处理
        cipher = cryptos.encrypt(source.encode())
        print(cipher)
        print(b2a_hex(cipher).decode())    #解码需要十六进制的编码
AES_en()

#1e15f0643d70c6a85f514bd44ea00d80    加密处理
#解密过程
def AES_de():

        key = 'wdawdwadawqw1231'.encode()
        mode = AES.MODE_CBC
        a = b'1231241214121123'
        cryptos = AES.new(key,mode,a)
        source = '1e15f0643d70c6a85f514bd44ea00d80'
        dest = cryptos.decrypt(a2b_hex(source))
        print(dest.decode().strip('\0'))   #以\0分隔开
AES_de()