'''
Descripttion: This is a simple code for filtering out wrong domain names in alexa and other domain name dataset.
version: 1.0
Author: Suliang Luo
Date: 2023-08-09 18:14:25
LastEditors: Please set LastEditors
LastEditTime: 2023-10-03 04:41:17
'''
import os
import re
import idna
import tqdm
import whois
import tldextract
import numpy as np
import pandas as pd
from tensorflow.keras.preprocessing.sequence import pad_sequences

root_dir = os.path.dirname(os.path.abspath(__file__))
vacal_chars = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-']
char2id = {char:i for i,char in enumerate(vacal_chars,start=1)}
id2char = {i:char for i,char in enumerate(vacal_chars,start=1)}
MAX_FEATURES = len(vacal_chars)


suffix_path = os.path.join(root_dir,"../asset/public_suffix_list.txt")
with open(suffix_path,'r',encoding="utf-8") as f:
    lines = f.readlines()
    suffix_list = [line.strip().lower() for line in lines]
f.close()


def is_valid_domain_name(domain_name):
    """
    Check if a domain name is valid.
    :param domain: str, the domain name to be checked.
    :return: bool, True if the domain name is valid, False otherwise.
    """   
    # 1.域名必须是字符串-----the domain name must be string
    if (not isinstance(domain_name, str)):
        return False
    
    # 2.域名长度不能超过255-----The domain name length can not exceed 255 according to the RFC definition
    if len(domain_name) > 255:                       
        return False
    
    # 3.域名要符合域名的命名规范-----The domain name meets the naming specification of the domain name, include consist of 26 letter(a-z), ten number(0-9), '-' and every segment less than 64
    pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
    judge = bool(re.match(pattern, domain_name)) and '_' not in domain_name
    if not judge:
        return False
    
    # 3.域名不能使用punycode编码的域名-----The domain names can not use punycode-encoded domain names
    name = domain_name.split('.')
    sfx = name[-1]
    md = name[-2]
    try:
        decode_domain = idna.decode(sfx)==sfx and idna.decode(md)==md
        # 如果decode_domain为True,说明是正常的域名,否则为punycode域名
    except:
        if(idna.decode(sfx)==sfx):
            decode_domain = True 
        else:
            decode_domain = False 
    if(not decode_domain):   
        return False
    
    # 4.域名后缀必须是public_suffix_list.txt中的后缀
    suff = tldextract.extract(domain_name).suffix         # 
    if suff not in suffix_list:
        return False
    
    # 5.域名必须是在whois中存在的域名, 如果是benign才要满足这个条件
    # WHOIS 信息查询结果可能因网络连接、WHOIS 服务器限制等原因而有所变化,某些域名可能会隐藏其 WHOIS 信息
    # flag = whois.whois(domain_name)
    # if(not flag.status):
    #     return False
    return True

def domain_extract(name):

    mdomain = tldextract.extract(name).domain
    subdomain = tldextract.extract(name).subdomain
    suffix = tldextract.extract(name).suffix
    domain =  subdomain + mdomain      #+ suffix                       # 这里是否应该加上suffix？不知道，反正基本上所有的相关研究都没加，可是我觉得后缀对于判断一个域名是否是恶意的也是很重要的一个特征

    return domain.replace('.','').lower()


# get orignal domain dataset
def get_data(file_path):

    """
    function: get the original data
    param:
        file_path: the path of the data
    """
    X = pd.Series(data=None,dtype=int)
    Y= []
    for root,dir,files in os.walk(file_path):
        for file_item in files: 
            output_path = os.path.join(root_dir,"data/filterData/"+file_item.split('.')[0]+".pkl")
            with open(output_path,'wb') as f:
                i = 0
                DGA = pd.DataFrame(columns=['domain','domain_trans','label'])           
                data_csv = pd.read_csv(os.path.join(root,file_item),header=None)[0]
                for idx,val in data_csv.items():
                    if(is_valid_domain_name(val)):
                        domain = domain_extract(val)
                        domain_trans = [valid_chars[y] for y in domain]
                        if('Tranco' in file_item):
                            item = [domain,domain_trans,0]
                        else:
                            item = [domain,domain_trans,1]
                        DGA.loc[i] = item
                        i += 1
                DGA = DGA.drop_duplicates(subset='domain') 
                DGA.to_pickle(f)
                print("file %s transform done\n"%output_path)
            f.close()
    return 0

if __name__=="__main__":
    get_data(os.path.join(root_dir,"data/dga"))
    