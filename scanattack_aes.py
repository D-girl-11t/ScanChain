#import required libraries
import subprocess
from Crypto.Cipher import AES           #lets use for testing because running an exe file and fetching output is taking time 
import itertools
import time

#for executing the given exe file for scan chains and 
def execute(input_inhex, clock_cycle):
    scan= subprocess.check_output("aes_scan_exam_ds6992_windows_amd64.exe -input="+input_inhex+" -clocks="+clock_cycle+" -emit_scan", shell=True)
    return scan

plain_text = "00000000000000000000000000000000"       #hex form -128 bits - 32 hexcharacters

# --------------------------------------------------------------------------------STEP1 - FINDING INPUT BITS------------------------------------------------------------------------------

#lets change bits and get different patterns of scan_chains
patterns =[]
scanchains=[]

# important
indices =[]

for i in range(32):
    for j in [8,4,2,1]:
        pattern =str(plain_text)[:i]+str(j)+str(plain_text)[i+1:]
        patterns.append(pattern)

        scanchain =str(str(execute(pattern, "1")).split("scan_chain:")[-1]).split("\\n")[0]

        indices.append(str(scanchain).index("1"))
        scanchains.append(scanchain)
        

# THE INPUT BITS ARE IN CORRESPONDING SCANCHAIN INDEX
input_bits={}
ibits = [i for i in range(128)]
for i in range(128):
    input_bits["input_"+str(i)] = indices[i]
# print(input_bits)
# print(list(zip(ibits, indices)))
# print(indices)
# print(len(indices))
# ---------------------------------------------step 2 data_bits------------------------------------

indices=list(set(indices))
databits_no_order=[]
for i in range(256):
    if i not in indices:
        databits_no_order.append(i)

#just defining the variables for outputbits
for h in range(128):
    globals()["output_bit"+str(h)]=[]

# getting outputs and scanchain for cycle 10 for each pattern
outputs=[]
scans=[]    #scan contains scanchains without input bits

for i in patterns:
    outputs.append(bin(int(str(str(execute(i, "10")).split("output:")[-1]).split("\\n")[0],16))[2:].zfill(128))
    scanchain = str(str(execute(i, "10")).split("scan_chain:")[-1]).split("\\n")[0]
    sc=""
    for o in range(256):
        if o not in indices:
            sc=sc+scanchain[o]
    scans.append(sc)

# xor the outputs - note the change of bits and their indices
# xor the scan chain 10 - note the change of bits and their indices 
for i in range(len(outputs)):
    for j in range(i+1,len(outputs)):
        x = bin(int(outputs[i],2)^int(outputs[j],2))[2:].zfill(128)
        xindices = [i for i in range(len(x)) if x[i]=="1"]
        # print(xindices)
        y = bin(int(scans[i],2)^int(scans[j],2))[2:].zfill(128)
        yindices = [i for i in range(len(y)) if y[i]=="1"]
        # print(yindices)
        for k in range(128):
            if k in xindices:
                globals()["output_bit"+str(k)].append(yindices)
    break

#determining databits by ANDing all the noted indices will result in 1 number - position of databit in scan chain
databits=[]
for i in range(128):
    res=set(globals()["output_bit"+str(i)][0])
    for h in globals()["output_bit"+str(i)]:
        res=res&set(h)
    # print(res)
    databits.append(databits_no_order[list(res)[0]])
# print(databits)


data_bits={}
for i in range(128):
    data_bits["data_"+str(i)] = databits[i]
# print(data_bits)


#the bits of scan chain are as follows
merged = {**input_bits, **data_bits}
scan_bits= {k: v for k, v in sorted(merged.items(), key=lambda item: item[1])}
print(scan_bits)

# # ----------------------------------------------------STEP2 finding rk0 - the user key--------------------------------------------


key = []            #possible key values
kk=""

for j in range(0,32, 2):            #for changing a byte in the plain_text
    pos_key=[]
    for i in range(127):            #for 0<=i<=127 according to the paper

        byte_a1 = str(hex(2*i))[2:]        #a1 is of the form 2i  
        if len(byte_a1)==1:
            byte_a1 = "0"+byte_a1        
        a1 = str(plain_text)[:j]+byte_a1+str(plain_text)[j+2:]
        sc1 =str(str(execute(a1,"2")).split("scan_chain:")[-1]).split("\\n")[0]

        byte_a2 = str(hex(2*i+1))[2:]        #a2 is of the form 2i+1
        if len(byte_a2)==1:
            byte_a2 = "0"+byte_a2
        a2 = str(plain_text)[:j]+byte_a2+str(plain_text)[j+2:]
        sc2 =str(str(execute(a2,"2")).split("scan_chain:")[-1]).split("\\n")[0]
        
        xor = str(bin(int(sc1,2)^int(sc2,2)))[2:]   #xor scan chains obatined by a1 and a2
        n = xor.count("1") -1                       #since it also conatins input bits and they differ only by 1, subtract 1 from number of 1's obtained by xor

        byte_a1 = int(byte_a1,16)   #convert to int
        byte_a2 = int(byte_a2,16)

        if n==9:        
            b1=226
            b2=227

            kk = kk + str(hex(byte_a1^b1))[2:].zfill(2)
            pos_key.append(str(hex(byte_a1^b1))[2:])
            pos_key.append(str(hex(byte_a1^b2))[2:])
            key.append(pos_key)
            break

        elif n==12:
            b1=242
            b2=243
           
            kk = kk + str(hex(byte_a1^b1))[2:].zfill(2)
            pos_key.append(str(hex(byte_a1^b1))[2:])
            pos_key.append(str(hex(byte_a1^b2))[2:])
            key.append(pos_key)
            break

        elif n==23:
            b1=122
            b2=123
            
            kk = kk + str(hex(byte_a1^b1))[2:].zfill(2)
            pos_key.append(str(hex(byte_a1^b1))[2:])
            pos_key.append(str(hex(byte_a1^b2))[2:])
            key.append(pos_key)
            break

        elif n==24:
            b1=130
            b2=131
          
            kk = kk + str(hex(byte_a1^b1))[2:].zfill(2)
            pos_key.append(str(hex(byte_a1^b1))[2:])
            pos_key.append(str(hex(byte_a1^b2))[2:])
            key.append(pos_key)
            break  

        # break
    # break

print(key)  #in hex
kk = str(bin(int(kk,16)))[2:].zfill(128)
print(kk)   #in bits

possibility =[]
for i in range(1,17):   #making all lsb of key byte to zero to start with
    kk = kk[:8*i-1] + "0" + kk[8*i:]


comb=[]         #combinations of lsb's
for c in itertools.product([0,1], repeat=16):
    comb.append(c)
    ss=kk
    for i in range(1,17):       #changing all lsb's
        ss= ss[:8*i-1] + str(c[i-1]) + ss[8*i:]
        if(len(ss)!=128):
            print("check")
        test=str(hex(int(ss,2)))[2:].zfill(32)

    possibility.append(test)


def aes_encrypt(key):
    enc_s = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    cipher_text = enc_s.encrypt(bytes.fromhex('00000000000000000000000000000000'))
    encoded_cipher_text = cipher_text.hex().zfill(32)
    return encoded_cipher_text

# print(len(possibility))
# start_time = time.time()
aes_key=""

cipher_output = str(str(execute(plain_text,"10")).split("output:")[-1]).split("\\n")[0]
print(cipher_output)
# "12A4F35209BEBA60023FD9C699872115" is the cipher of "00000000000000000000000000000000"
for i in possibility:
    # out = str(execute(i, "10")).split("output:")[-1].split("\\n")[0] #could use this method too but it is time taking
    out = aes_encrypt(i)
    if(out ==cipher_output.lower()):        
        aes_key=i
        print(i)
        break
    # break
# print("--- %s seconds ---" % (time.time() - start_time))
print("the key is "+aes_key)