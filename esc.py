from base64 import b64decode
import json
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b


class PEM_analyzer:
    
    def __init__(self,int_type=hex) -> None:
        self.is_private = None
        self.type = hex
        
        if int_type == bin:
            self.type = bin
        
        elif int_type == int:
            self.type = int
        
    
    class NotImplementedError(Exception):
        pass

    
    def import_pem(self, pem_data):

        if "-----BEGIN PRIVATE KEY-----" in pem_data:
            pem_data = pem_data.replace("-----BEGIN PRIVATE KEY-----","").replace("-----END PRIVATE KEY-----","")
            self.is_private = True
        elif "-----BEGIN PUBLIC KEY-----" in pem_data:
            self.is_private = False
            pem_data = pem_data.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----","")
        else:
            print("not supported")
            exit()
        
        pem_data = pem_data.replace("\n","")
        
        return self.extract_ans1(b64decode(pem_data))

    def extract_ans1(self, data):
        
        tags = {
            0x02 : "INTEGER",
            0x03 : "BIT STRING",
            0x04 : "OCTET STRING",
            0x05 : "NULL",
            0x06 : "OBJECT IDENTIFIER",
            0x0c : "UTF8String",
            0x10 : "SEQUENCE",
            0x30 : "SEQUENCE OF",
            0x11 : "SET",
            0x31 : "SET OF",
            0x13 : "PrintableString",
            0x16 : "IA5String",
            0x17 : "UTCTime",
            0x18 : "GeneralizedTime",
                }

        tag_class = {
            0: "universal",
            1: "application",
            2: "context-specific",
            3: "private",
        }

        def header_extract(data,json_data):
            
            if  not data[0] in tags:
                raise NotImplementedError(f"{data[0]} is not in tags") 
            if "SEQUENCE" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]
                
                # data_len
                if data[1] >> 7 ==1:
                    usebytes = data[1]&0xF
                    data_len = b2l(data[2:2+usebytes])
                    data = data[2+usebytes:]
                    
                
                else:
                    data_len = int(data[1])
                    data = data[2:]
                
                json_data["len(bytes)"] = data_len
                json_data["data"] = []
                
                remain_data = data[data_len:]
                
                while data!=b"":
                    data, json_data_child = header_extract(data[:data_len],dict())
                    json_data["data"].append(json_data_child)

                return remain_data, json_data
       
            elif "INTEGER" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]

                # data_len
                base = 1
                usebytes = 2
                if data[1] >> 7 ==1:
                    usebytes += data[1]&0xF
                    base = 2
                    
                data_len = b2l(data[base:usebytes])
                value = b2l(data[usebytes:usebytes+data_len])
                
                if self.type == bin:
                    value = "0b"+bin(value)[2:].zfill(data_len*8)

                elif self.type == hex:
                    value = "0x"+hex(value)[2:].zfill(data_len)

                
                data = data[usebytes+data_len:]
                json_data["len(bytes)"] = data_len
                json_data["value"] = value
                
                return data, json_data
            
            elif "OBJECT IDENTIFIER" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]
                
                if data[:11].hex() == "06092a864886f70d010101":
                    json_data["OID"] = "RSA"
                    data = data[11:]
                else:
                    print("NOT IMPL")
                    exit()
                
                return data, json_data                

            elif "NULL" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]
                if int(data[1]) == 0:
                    data = data[2:]
                else:
                    print("NOt impl")
                    exit()

                return data, json_data      
                   
            elif "OCTET STRING" in tags[data[0]]:
                
                # data_len
                if data[1] >> 7 ==1:
                    usebytes = data[1]&0xF
                    data_len = b2l(data[2:2+usebytes])
                    data = data[2+usebytes:]
                    
                else:
                    data_len = int(data[1])
                    data = data[2:]
                
                json_data["len(bytes)"] = data_len
                json_data["data"] = []
                remain_data = data[data_len:]
                
                while data!=b"":
                    data, json_data_child = header_extract(data[:data_len],dict())
                    json_data["data"].append(json_data_child)

                return remain_data, json_data

            else:
                raise NotImplementedError(f"{tags[data[0]]} is not impl") 
            
        json_data = dict()    
        ret =  header_extract(data, json_data)
        return json.dumps(ret[1], indent=2)

if __name__ == "__main__":
    print(PEM_analyzer(int).import_pem(open("./test/ca-privatekey.pem").read()))


