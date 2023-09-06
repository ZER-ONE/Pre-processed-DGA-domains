'''
Descripttion: 
version: 1.0
Author: Suliang Luo
Date: 2023-08-09 18:14:25
LastEditors: Please set LastEditors
LastEditTime: 2023-08-28 02:02:04
'''
import os
import re
import tldextract
import numpy as np
import pandas as pd
import tqdm
from tensorflow.keras.preprocessing.sequence import pad_sequences

vacal_chars = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','-']
# Generate a dictionary of valid characters
valid_chars = {item: idx for idx, item in enumerate(vacal_chars,start=1)}


MAX_FEATURES = len(vacal_chars)
root_dir = os.path.dirname(os.path.abspath(__file__))

# 没有过滤完全，可能存在punycode的域名，比如说xn--开头的域名，但是是以public_suffix后缀结尾的域名
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
    if (not isinstance(domain_name, str)):
        return False
    if len(domain_name) > 255:                       # 域名长度不能超过255
        return False
    
    pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,6}$'
    judge = bool(re.match(pattern, domain_name)) and '_' not in domain_name
    if not judge:
        return False
    
    suff = tldextract.extract(domain_name).suffix         # 其实这里就可以清除掉punycode域名了，因为punycode的域名后缀是xn--开头的，并不在public_suffix_list.txt中
    if suff not in suffix_list:
        return False
    
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
        label: the label of the data       
    :return: X: train data
                Y: train label          
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
    