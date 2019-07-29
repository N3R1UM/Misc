#!/usr/bin/python
# -*- coding: UTF-8 -*-

import re
import sys
import base64

# Version 1.0.2
vsn = '1.0.2'
# Update : Support Caesar Ciphter Decoder And Fixed Other Bugs
# Edit By Team Called Dynamic Programming Security Team.
# Created Time : 2018/10/16
# Last Edit Time : 2018/10/22, Last Editer : Nerium

param = sys.argv[1:]

# Check Anwser In
# Time : 2018/10/16
# Edit : Nerium
def check_in(d_ans) :
    temp = ['ctf','CTF','flag','FLAG']
    for i in temp :
        if i in d_ans and( '[' in d_ans or '{' in d_ans or '(' in d_ans) :
	    return True
    return False



# BASE64 Decode
# Time : 2018/10/17
# Edit : Nerium
def b64(d_enc):
    try :
	ret = base64.b64decode(d_enc)
    except :
        ret = 'ERROR 1 : This magic string\'s format is wrong for base64'
    return ret



# BACON Decode
# Time : 2018/10/17
# Edit : Nerium
def bac(d_enc) :

    alphabet = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
    first_cipher = ["aaaaa","aaaab","aaaba","aaabb","aabaa","aabab","aabba","aabbb","abaaa","abaab","ababa","ababb","abbaa","abbab","abbba","abbbb","baaaa","baaab","baaba","baabb","babaa","babab","babba","babbb","bbaaa","bbaab"]
    second_cipher = ["aaaaa","aaaab","aaaba","aaabb","aabaa","aabab","aabba","aabbb","abaaa","abaaa","abaab","ababa","ababb","abbaa","abbab","abbba","abbbb","baaaa","baaab","baaba","baabb","baabb","babaa","babab","babba","babbb"]
    flag = False
    if d_enc.isupper():
        flag = True
        d_enc = d_enc.lower()
    t_array = re.findall('.{5}',d_enc)
    ans1 = ''
    ans2 = ''
    for i in t_array:
        for j in range(0,26):
            if i == first_cipher[j]:
                ans1 += alphabet[j]
            if i == second_cipher[j]:
                ans2 += alphabet[j]
        if flag:
            ans1 = ans1.upper()
            ans2 = ans2.upper()
        return ans1 + ans2



# CRC32 Decode
# Time : 
# Edit : 
def crc() :
    pass


# %26 Caesar Helpr
# Time : 2018/10/22
# Edit : Nerium
def mod26(d_enc) :
    if d_enc >= 26 :
        d_enc -= 26
    elif d_enc < 0 :
        d_enc += 26
    return d_enc



# Caesar Decode
# Time : 2018/10/22
# Edit : Nerium
def csr(d_enc, d_ipt) :
    
    lower_ciphter = 'abcdefghijklmnopqrstuvwxyz'
    upper_ciphter = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    if d_ipt != '' :
        d_ipt = int(d_ipt) % 26
        ans = ''
        for i in d_enc :
            num = -1
            if i in lower_ciphter :
                num = lower_ciphter.find(i)
                num -= d_ipt
                ans += lower_ciphter[mod26(num)]
            elif i in upper_ciphter and num == -1 :
                num = upper_ciphter.find(i)
                num -= d_ipt
                ans += upper_ciphter[mod26(num)]
            else :
                ans += i
        return ans
    else :
        for j in range(1,27) :
            ans = ''
            for i in d_enc :
                num = -1
                if i in lower_ciphter :
                    num = lower_ciphter.find(i)
                    num -= j
                    ans += lower_ciphter[mod26(num)]
                elif i in upper_ciphter and num == -1 :
                    num = upper_ciphter.find(i)
                    num -= j
                    ans += upper_ciphter[mod26(num)]
                else :
                    ans += i
            if check_in(ans) :
                return ans



# Hex Decode
# Time : 2019/07/29
# Edit : Nerium
def Hex(d_enc) :
    if '0x' in d_enc :
        t_enc = d_enc.replace('0x','')
    else :
        t_enc = d_enc
    if '\\x' in d_enc :
        d_enc = t_enc.replace('\\x','')
    else :
        d_enc = t_enc
    try :
        ans = ''
        for i in range(len(d_enc)//2) :
            ans += chr(int('0x'+d_enc[2*i]+d_enc[(2*i)+1],16))
        return ans
    except :
        return 'ERROR 2 : This magic string\'s format is wrong for hex'



# Hill Decode
# Time : 2018/10/19
# Edit : Nerium
def hil(t_enc) :
    dic = {chr(i+96): i for i in range(1, 27)}

    ciphertext = d_enc
    public_key = matrix(array([[1, 2],
                               [0, 1]]))

    public_key_inverse = public_key.I
    temp = public_key_inverse.tolist()
    
    for i in range(len(public_key)):
        for j in range(len(public_key)):
            temp[i][j] = int(str(temp[i][j]).split('.')[0])
    public_key_inverse = matrix(temp)

    temp = []
    result = []
    for i in text:
        temp.append(dic.get(i))
    temp = array(temp)
    temp = temp.reshape(len(text)/len(public_key), len(public_key))
    temp = matrix(temp).T
    
    xx = public_key*temp
    
    for i in range(len(text)/len(public_key)):
        for j in range(len(public_key)):
            result.append(chr(xx[j, i] % 26 + 96))

    return "".join(result)



# MD5 Decode
# Time : 
# Edit : 
def mdf() :
    #Post magic string to some md5 decode website get return result
    pass



# XOR Decode
# Time : 2018/10/18
# Edit : Nerium
def xr(d_enc, d_ipt) :
    if d_ipt == '' :
        #Don't know the key, try to exploit it
        for i in range(31,128) :
    	    ans = ''
	    for k in d_enc :
		ans += chr(ord(k) ^ i)
	    if check_in(ans) :
	        return ans
        return 'ERROR 3 : Do not find flag. Maybe you can use other decoders before or continue to decode'
    else :
        if len(d_ipt) == len(d_enc) :
            #Same len, then one to one xor
    	    ans = ''
	    for i in range(len(d_enc)) :
	        ans += chr(ord(d_enc[i]) ^ ord(d_ipt[i]))
	    return ans
        elif len(d_ipt) == 1 :
            #Key is one bytes, know the key
            ans = ''
            for i in d_enc :
                ans += chr(ord(i) ^ d_ipt)
            return ans
        else :
            return xr(d_enc, '')



# Welcome Show
# Time : 2018/10/18
# Edit : Nerium
def welcome() :
    print ''
    print ''
    print 'WELCOME TO DEMAGIC ', vsn
    print '______            ______'
    print '\     \          /     /'
    print ' \     \        /     / '
    print '  \     \      /     /  '
    print '   \     \    /     /   '
    print '    \     \  /     /    '
    print '     \     \/     /     '
    print '      \          /      '
    print '       \        /       '
    print '        \______/        '
    print 'JUST       FUN        IT'



# Show Help
# Time : 2018/10/22
# Edit : Nerium
def show_info() :
    print ''
    print ''
    print 'DeMagic Version ', vsn
    print 'Use This Command To Run It : python demagic.py param1 param2 ... '
    print 'The order by paramter is decode order. First use param1 to decode then use 2 and continue'
    print '\tb64 \tUse base64 to decode'
    print '\tbac \tUse bacon to decode'
    print '\tcrc \tNow do not support it'
    print '\tcsr \tUse ceasar to decode, if you don\'t know the key, \'csr\' must be last'
    print '\thex \tTranslate hex'
    print '\thil \tBase hill matrix to decode. Maybe not work'
    print '\tmd5 \tNow do not support it'
    print '\txor \tUse xor to decode, if you don\'t know the key, \'xor\' must be last'
    print '\t... \tPlease wating for update'
    print '\thelp\tShow Help Maybe Can Help You'
    print ''
    print ''



# Chekcked System Paramter
# Time : 2018/10/22
# Edit : Nerium
def checked(t_param, enc) :
    t_enc = enc
    for no in t_param :
        if no == 'b64' :
            t_enc = b64(t_enc)
        elif no == 'bac' :
            t_enc = bac(t_enc)
        elif no == 'crc' :
            t_enc = crc(t_enc)
        elif no == 'csr' :
            print 'Do You Know The Key ? :'
            ipt = raw_input()
            t_enc = csr(t_enc, ipt)
        elif no == 'hex' :
            t_enc = Hex(t_enc)
        elif no == 'hil' :
            t_enc = hil(t_enc)
        elif no == 'md5' :
            t_enc = mdf(t_enc)
        elif no == 'xor' :
            print 'Do You Know The Key ？ :'
            ipt = raw_input()
            t_enc = xr(t_enc, ipt) 
        else :
            show_info()
        if 'ERROR' in t_enc :
            break
    if 'ERROR' not in t_enc :
        if check_in(t_enc) :
            return '\033[1;31;40m'+t_enc+'\033[0m'
        else :
            return '\033[1;31;40mDo not find flag. Please try other orders or decoders\033[0m'
    else :
        return '\033[1;31;40m'+t_enc+'\033[0m'



# Main Function
# Time : 2018/10/22
# Edit : Nerium
def main() :

    now_decode = ['b64','bac','cc','csr','hex','hil','md5','xor']
    
    if len(param) == 0 :
        show_info()
        sys.exit(0)
    for i in param :
	    if i not in now_decode :
	        show_info()
	        sys.exit(0)

    welcome()
    question = raw_input('Please Input Your Magic String\n[Input Nothing To Escape Off (≧∇≦)ﾉ]\n')
    if question == '' :
        return
    print checked(param, question)



if __name__ == "__main__" :
    main()