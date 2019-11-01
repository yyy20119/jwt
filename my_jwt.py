import base64
import copy
import hmac
import json
import time


class Jwt():
    def __init__(self):
        pass

    @staticmethod
    def b64encode(j_s):
        return base64.urlsafe_b64encode(j_s).replace(b'=',b'')

    @staticmethod
    def b64decode(b_s):
        #补全签发时替换掉的等号
        rem=len(b_s)%4
        if rem>0:
            b_s+=b'=' * (4-rem)
        return base64.urlsafe_b64decode(b_s)


    @staticmethod
    def encode(payload,key,exp=300):
        #init header
        header={'typ':'JWT','alg':'HS256'}
        header_json=json.dumps(header,sort_keys=True,separators=(',',':'))
        header_bs=Jwt.b64encode(header_json.encode())

        #payload
        my_payload=copy.deepcopy(payload)
        my_payload['exp']=time.time()+int(exp)
        payload_json=json.dumps(my_payload,sort_keys=True,separators=(',',':'))
        payload_bs=Jwt.b64encode(payload_json.encode())

        #sign
        if isinstance(key,str):
            key=key.encode()
        hm=hmac.new(key,header_bs+b'.'+payload_bs,digestmod='SHA256')
        hm_bs=Jwt.b64encode(hm.digest())

        return header_bs+b'.'+payload_bs+b'.'+hm_bs


    @staticmethod
    def decode(jwt_s,key):
        header_bs,payload_bs,sign_bs=jwt_s.split(b'.')
        if isinstance(key,str):
            key=key.encode()
        hm=hmac.new(key,header_bs+b'.'+payload_bs,digestmod='SHA256')
        new_sign_bs=Jwt.b64encode(hm.digest())
        if new_sign_bs != sign_bs:
            raise Exception('token错误')
        #检查payload中的时间
        payload_json=Jwt.b64decode(payload_bs)
        #json字符串
        payload=json.loads(payload_json)
        exp=payload['exp']
        now_t=time.time()
        if now_t>exp:
            raise Exception('已过期')
        return payload


if __name__ == '__main__':
    s=Jwt.encode({'username':'yty'},'123456',300)
    time.sleep(101)
    d=Jwt.decode(s,'123456')
    print(d)




