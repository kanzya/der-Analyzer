from base64 import b64decode
import json
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
import re
from logging import getLogger, basicConfig, INFO


logger = getLogger(__name__)
basicConfig(level=INFO)
logger.info('this is good logging')


class PEM_analyzer:

    def __init__(self, int_type=hex) -> None:
        self.hidden = None

        if int_type in (bin, int, hex):
            self.type = int_type
        else:
            NotImplementedError("not supported type of f{int_type}")

    def import_pem(self, pem_data: bytes):

        if not (("BEGIN" in pem_data) or ("END" in pem_data)):
            raise NotImplementedError("not supported or broken")

        if "-----BEGIN PRIVATE KEY-----" in pem_data:
            pem_data = pem_data.replace(
                "-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "")
            self.is_private = True
        elif "-----BEGIN PUBLIC KEY-----" in pem_data:
            self.is_private = False
            pem_data = pem_data.replace(
                "-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "")

        elif "-----BEGIN RSA PRIVATE KEY-----" in pem_data:
            pem_data = pem_data.replace(
                "-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "")
            self.is_private = True
        elif "-----BEGIN RSA PUBLIC KEY-----" in pem_data:
            self.is_private = False
            pem_data = pem_data.replace(
                "-----BEGIN RSA PUBLIC KEY-----", "").replace("-----END RSA PUBLIC KEY------", "")

        else:
            raise NotImplementedError("not supported or broken")

        pem_data = pem_data.replace("\n", "")

        # can recover broken
        b64_pattern = "[a-zA-Z0-9+/=]+"
        re_test = re.sub(b64_pattern, "", pem_data)

        if re_test != "":
            if len(set([r for r in re_test])) == 1:
                logger.warning(f"only \"{re_test[0]}\" is found its mean hidden charactor...??")
                self.hidden = re_test[0]
            else:
                raise NotImplementedError(f"{set([r for r in re_test])} is found in pem, we cant decode")

        if self.hidden == None:
            logger.info("looks collect file")
            return self.extract_ans1(b64decode(pem_data))

        else:
            return self.analyze_broken(pem_data)

    def analyze_broken(self, data):

        logger.info("try extract to binarry value ")
        logger.info("set to type of int is bin")

        self.type = bin
        ret00 = self.extract_ans1(b64decode(data.replace(self.hidden, "A")))
        retff = self.extract_ans1(b64decode(data.replace(self.hidden, "/")))

        # need to more efficient impl
        diff = [ret00_i == retff_i for ret00_i, retff_i in zip(str(ret00), str(retff))]
        return json.dumps(eval("".join([ret00_i if diff_i else "*" for diff_i, ret00_i in zip(diff, ret00)])), indent=2)

    def extract_ans1(self, data):

        tags = {
            0x02: "INTEGER",
            0x03: "BIT STRING",
            0x04: "OCTET STRING",
            0x05: "NULL",
            0x06: "OBJECT IDENTIFIER",
            0x0c: "UTF8String",
            0x10: "SEQUENCE",
            0x30: "SEQUENCE OF",
            0x11: "SET",
            0x31: "SET OF",
            0x13: "PrintableString",
            0x16: "IA5String",
            0x17: "UTCTime",
            0x18: "GeneralizedTime",
        }

        tag_class = {
            0: "universal",
            1: "application",
            2: "context-specific",
            3: "private",
        }

        def header_extract(data, json_data):

            if not data[0] in tags:
                raise NotImplementedError(f"{data[0]} is not in tags")

            if "SEQUENCE" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]

                # data_len
                if data[1] >> 7 == 1:
                    usebytes = data[1] & 0xF
                    data_len = b2l(data[2:2 + usebytes])
                    data = data[2 + usebytes:]

                else:
                    data_len = int(data[1])
                    data = data[2:]

                json_data["len(bytes)"] = data_len
                json_data["data"] = []

                remain_data = data[data_len:]

                while data != b"":
                    data, json_data_child = header_extract(
                        data[:data_len], dict())
                    json_data["data"].append(json_data_child)

                return remain_data, json_data

            elif "INTEGER" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]

                # data_len
                base = 1
                usebytes = 2
                if data[1] >> 7 == 1:
                    usebytes += data[1] & 0xF
                    base = 2

                data_len = b2l(data[base:usebytes])
                value = b2l(data[usebytes:usebytes + data_len])
                if self.type == bin:
                    value = "0b" + bin(value)[2:].zfill(data_len * 8)

                elif self.type == hex:
                    value = "0x" + hex(value)[2:].zfill(data_len)

                data = data[usebytes + data_len:]
                json_data["len(bytes)"] = data_len
                json_data["value"] = value

                return data, json_data

            elif "OBJECT IDENTIFIER" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]

                if data[:11].hex() == "06092a864886f70d010101":
                    json_data["OID"] = "RSA"
                    data = data[11:]
                else:
                    raise NotImplementedError(f"not impl oid {data[11:].hex()}")

                return data, json_data

            elif "NULL" in tags[data[0]]:
                json_data["tag"] = tags[data[0]]
                if int(data[1]) == 0:
                    data = data[2:]
                else:
                    raise NotImplementedError(f"eroor of NULL is {int(data[1])}")

                return data, json_data

            elif "OCTET STRING" in tags[data[0]]:

                # data_len
                if data[1] >> 7 == 1:
                    usebytes = data[1] & 0xF
                    data_len = b2l(data[2:2 + usebytes])
                    data = data[2 + usebytes:]

                else:
                    data_len = int(data[1])
                    data = data[2:]

                json_data["len(bytes)"] = data_len
                json_data["data"] = []
                remain_data = data[data_len:]

                while data != b"":
                    data, json_data_child = header_extract(
                        data[:data_len], dict())
                    json_data["data"].append(json_data_child)

                return remain_data, json_data

            else:
                raise NotImplementedError(
                    f"tag of {tags[data[0]]} is not impl")

        json_data = dict()
        ret = header_extract(data, json_data)
        return json.dumps(ret[1], indent=2)


if __name__ == "__main__":
    print(PEM_analyzer(hex).import_pem(open("./test/2048_0.pem").read()))
    print(PEM_analyzer().import_pem(open("./test/2048_2.pem").read()))
    print(PEM_analyzer().import_pem(open("./test/2048_3.pem").read()))
    print(PEM_analyzer().import_pem(open("./test/4096.pem").read()))
    print(PEM_analyzer().import_pem(open("./test/ca-privatekey.pem").read()))
