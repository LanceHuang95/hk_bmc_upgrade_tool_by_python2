脚本提取Eeprom资源树对象的SR数据
使用方法
1. 执行命令收集BlockIO读取Eeprom的数据 到 /tmp 目录下
2. ftp下载Eeprom*.txt到本地，放到名为eep的文件夹下
3. 执行 extract_blockio.py 脚本
使用方法
1. 执行命令收集BlockIO读取Eeprom的数据 到 /tmp 目录下
```shell
busctl --user tree bmc.kepler.hwproxy | grep -o Eeprom_.* | while read line; do if [[ $line != Eeprom_PsuChip* ]]; then busctl --user call bmc.kepler.hwproxy /bmc/kepler/Chip/Eeprom/$line bmc.kepler.Chip.BlockIO Read a{ss}uu 0 0 16384 > /tmp/$line.txt; fi done;chmod 777 /tmp/Eeprom*.txt
```
需要等待一分钟左右，执行完毕后会将资源树上所有Eeprom对象的读取数据保存到/tmp下的txt文件


2. ftp下载Eeprom*.txt到本地，放到名为eep的文件夹下


3. 执行 extract_blockio.py 脚本
python extract_blockio.py .
执行结果：输出sr文件到sr目录下
```py
#! /usr/bin/python3

import gzip
import sys
import os
import json
from pathlib import Path

def main(args):
    dest_dir = Path(args[0]) if args else Path(__file__).parent
    eep_dir = dest_dir.joinpath("eep")
    if not os.path.exists(eep_dir):
        eep_dir = dest_dir
    sr_dir = dest_dir.joinpath("sr")
    if not os.path.exists(sr_dir):
        os.makedirs(sr_dir, exist_ok=True)

    for eep_file in os.scandir(eep_dir):
        if not eep_file.is_file() or not eep_file.name.endswith('.txt'):
            continue
        
        with open(Path(eep_file), 'r') as f:
            content = f.readline()[:-1]

        arr = content.split(' ')
        if not arr[0].isdigit():
            arr = arr[2:]

        basename = Path(eep_file).stem
        try:
            arr = [int(num) for num in arr]
            psr_offset = (arr[20] * 256 + arr[19]) * 8
            csr_offset = (arr[22] * 256 + arr[21]) * 8
            sig_offset = (arr[24] * 256 + arr[23]) * 8
            data_version = f"{arr[99]}.{arr[98]:02d}"
            uid = bytearray(arr[100:124]).decode()
            if psr_offset != 0:
                psr_data = bytearray(arr[(psr_offset + 56):csr_offset])
                psr_str = gzip.decompress(psr_data).decode()
                if psr_str:
                    with open(sr_dir.joinpath(f"{basename}_PSR.sr"), 'w') as f:
                        json.dump(json.loads(psr_str), f, indent=4)
            
            if csr_offset != 0:
                csr_data = bytearray(arr[(csr_offset + 56):sig_offset])
                csr_str = gzip.decompress(csr_data).decode()
                if csr_str:
                    with open(sr_dir.joinpath(f"{basename}_CSR.sr"), 'w') as f:
                        json.dump(json.loads(csr_str), f, indent=4)
            print(f"[{basename}] DataVersion: {data_version}, UID: {uid}")
        except Exception as e:
            print(f"{basename} 数据异常：{e}")


if __name__ == "__main__":
    main(sys.argv[1:])
```

用busctl BlockIO将硬件自描述二进制文件烧录在EEPROM上
操作方法
结果
具体介绍
1. 二进制文件转化为 U8 字节流文本
2. 解除 RTOS 系统写保护
3. 获取EEPROM对象和负责写保护的Accessor对象，并去除EEPROM对象的写保护
4. 写入和读取命令
操作方法
解压附件得到eeprom文件夹，将要烧录的二进制文件放到eeprom文件夹里

image.png

用FTP连接bmc环境，将eeprom文件夹上传到/tmp目录下

image.png

用telnet协议登录bmc环境，执行以下命令（参数1是二进制文件名，参数2选择烧录到 BCU/EXU/SEU/CLU/IEU，实际使用的命令不带中括号）

cd /tmp/eeprom; bash test.sh [二进制文件名] [BCU/EXU/SEU/CLU/IEU]
结果
执行以上命令后需要等待一两分钟（取决于二进制文件大小），最终输出包含写入和读取的字节流，以及比较的结果

image.png

image.png

具体介绍
1. 二进制文件转化为 U8 字节流文本
用xxd将二进制文件转化为 U8 字节流文本

image.png

2. 解除 RTOS 系统写保护
source /etc/profile; if [ -e "/data/home/bmcdfx" ]; then cd /data/home; /data/home/bmcdfx emmc disable writeProtect 4; /data/home/bmcdfx emmc disable writeProtect 5; /data/home/bmcdfx emmc disable writeProtect 6; else cd /data; /data/bmcdfx emmc disable writeProtect 4; /data/bmcdfx emmc disable writeProtect 5; /data/bmcdfx emmc disable writeProtect 6; fi; mount -o rw,remount /; cd -
输出以下结果说明解除成功
屏幕截图 2022-12-16 110306.jpg

3. 获取EEPROM对象和负责写保护的Accessor对象，并去除EEPROM对象的写保护
image.png

4. 写入和读取命令
busctl --user call bmc.kepler.hwproxy /bmc/kepler/Chip/Eeprom/$Eeprom bmc.kepler.Chip.BlockIO Write a{ss}uay 0 $offset $count $line
busctl --user call bmc.kepler.hwproxy /bmc/kepler/Chip/Eeprom/$Eeprom bmc.kepler.Chip.BlockIO Read a{ss}uu 0 0 $length

```shell
#!/bin/bash

set -e

if [ "$#" -ne 2 ]; then
    echo "Usage: test.sh [binary file] [BCU/EXU/SEU/CLU/IEU]"
    exit 1
fi

if [[ "$2" != "BCU" && "$2" != "EXU" && "$2" != "SEU" && "$2" != "CLU" && "$2" != "IEU" ]]; then
    echo "Usage: test.sh [binary file] [BCU/EXU/SEU/CLU/IEU]"
    exit 1
fi

if [ ! -f "$1" ]; then
    echo "binary file not found"
    exit 1
fi

source /etc/profile

# 去除环境写保护
if [ -e "/data/home/bmcdfx" ]; then
    cd /data/home
    /data/home/bmcdfx emmc disable writeProtect 4
    /data/home/bmcdfx emmc disable writeProtect 5
    /data/home/bmcdfx emmc disable writeProtect 6
elif [ -e "/data/bmcdfx" ]; then
    cd /data
    /data/bmcdfx emmc disable writeProtect 4
    /data/bmcdfx emmc disable writeProtect 5
    /data/bmcdfx emmc disable writeProtect 6
fi
mount -o rw,remount /

cp -r /tmp/eeprom /root/
cd /root/eeprom
chmod -R 777 ./

# 二进制转U8字节流
./xxd -g 1 $1 | cut -d " " -f 2-19 | awk '{
line="";
for(i = 1; i < NF; ++i){
    line=sprintf("%s%d ", line, "0x" $i)
}
print line
}' > u8.data

# 获取EEPROM对象和负责写保护的Accessor对象
Accessor=`busctl --user tree bmc.kepler.hwproxy | grep -o Accessor_${2}WP_.* -m 1`
Eeprom=`echo $Accessor | sed 's/Accessor/Eeprom/; s/WP//'`

# 去除EEPROM写保护
busctl --user set-property bmc.kepler.hwproxy /bmc/kepler/Accessor/$Accessor bmc.kepler.Accessor Value t 0


# 先写入到EEPROM，然后读取相同长度，比较是否与写入的相同
offset=0
initial_offset=0
input_str=""
while read line; do 
    if [ ! "$line" ]; then
        break
    fi
    spaces="${line//[^ ]}"
    count="${#spaces}"
    count=$(( count+1 ))

    busctl --user call bmc.kepler.hwproxy /bmc/kepler/Chip/Eeprom/$Eeprom bmc.kepler.Chip.BlockIO Write a{ss}uay 0 $offset $count $line

    input_str=$input_str$line" "
    offset=$(( offset+count ))
done < u8.data

length=$(( offset-initial_offset ))

input_str="${input_str::-1}"

output_str=`busctl --user call bmc.kepler.hwproxy /bmc/kepler/Chip/Eeprom/$Eeprom bmc.kepler.Chip.BlockIO Read a{ss}uu 0 0 $length`

input_str="ay $length "$input_str

echo '写入：'
echo $input_str

echo '读取：'
echo $output_str
if [ "$input_str" == "$output_str" ]; then
    echo "读取与写入相同"
else
    echo "读取与写入不同"
fi
```
