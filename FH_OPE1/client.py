#print("编码树分裂: sudo tail -f /var/log/mysql/error.log")
import pymysql
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

local_table = {}
key = get_random_bytes(16)
base_iv = get_random_bytes(16)

def AES_ENC(plaintext, iv):
    #AES加密
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(plaintext, AES.block_size, style='pkcs7')
    ciphertext = aes.encrypt(padded_data)
    return ciphertext

def AES_DEC(ciphertext, iv):
    #AES解密
    aes = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = aes.decrypt(ciphertext)
    plaintext = unpad(padded_data, AES.block_size, style='pkcs7')
    return plaintext

def Random_Encrypt(plaintext):
    #随机生成iv来保证加密结果的随机性
    iv = get_random_bytes(16)
    ciphertext = AES_ENC(iv + AES_ENC(plaintext.encode('utf-8'), iv), base_iv)
    ciphertext = base64.b64encode(ciphertext)
    return ciphertext.decode('utf-8')

def Random_Decrypt(ciphertext):
    plaintext = AES_DEC(base64.b64decode(ciphertext.encode('utf-8')), base_iv)
    plaintext = AES_DEC(plaintext[16:], plaintext[:16])
    return plaintext.decode('utf-8')

def CalPos(plaintext):
    #插入plaintext,返回对应的Pos
    presum = sum([v for k, v in local_table.items() if k < plaintext])
    if plaintext in local_table:
        local_table[plaintext] += 1
        return random.randint(presum, presum + local_table[plaintext] - 1)
    else:
        local_table[plaintext] = 1
        return presum

def GetLeftPos(plaintext):
    return sum([v for k, v in local_table.items() if k < plaintext])

def GetRightPos(plaintext):
    return sum([v for k, v in local_table.items() if k <= plaintext])

def Insert(plaintext):
    ciphertext = Random_Encrypt(plaintext)
    #连接数据库
    conn = pymysql.connect(host='localhost', user='user', passwd='123456', database='test_db')
    cur = conn.cursor()
    cur.execute("call pro_insert(%s, %s)", (CalPos(plaintext), ciphertext))
    conn.commit()
    conn.close()


def InsertObserve(plaintext):
    conn = pymysql.connect(host='localhost', user='user', passwd='123456', database='test_db')
    cur = conn.cursor()
    cur.execute("select encoding, ciphertext from example")
    before = dict((ct, enc) for enc, ct in cur.fetchall())
    pos = CalPos(plaintext)
    ciphertext = Random_Encrypt(plaintext)
    cur.execute("call pro_insert(%s, %s)", (pos, ciphertext))
    conn.commit()
    cur.execute("select encoding, ciphertext from example")
    after = dict((ct, enc) for enc, ct in cur.fetchall())
    changed = sum(1 for ct, enc in before.items() if after.get(ct) != enc)
    conn.close()
    return pos, after.get(ciphertext), changed

def Search(left, right):
    #搜索[left,right]中的信息
    left_pos = GetLeftPos(left)
    right_pos = GetRightPos(right)
    #连接数据库
    conn = pymysql.connect(host='localhost', user='user', passwd='123456', database='test_db')
    cur = conn.cursor()
    cur.execute(
        "select ciphertext from example where encoding >= FHSearch(%s) and encoding < FHSearch(%s)",
        (left_pos, right_pos)
    )
    rest = cur.fetchall()
    for x in rest:
        print("ciphertext: {} plaintext: {}".format(x[0], Random_Decrypt(x[0])))

if __name__ == '__main__':
    # 不断插入相同明文，观察编码更新；分裂请查 MySQL 日志中的 [SPLIT]
    times, word = 200, 'apple'
    print("重复插入测试: '{}' x {}".format(word, times))
    recode_at = []
    for i in range(1, times + 1):
        pos, encoding, changed = InsertObserve(word)
        if changed:
            recode_at.append(i)
        if changed or i <= 5 or i % 10 == 0 or i == times:
            msg = "[{}/{}] pos={} encoding={}".format(i, times, pos, encoding)
            if changed:
                msg += " << Recode, {}条encoding更新".format(changed)
            print(msg)
    print("Recode次数: {} -> {}".format(len(recode_at), recode_at or '无'))
