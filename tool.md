使用方法：./hpm_unpack hpm_file <rootfs_output_tar_gz> <uboot_output_img>，其中：

hpm_file为待解的hpm包，注意，上述命令会剥离hpm包的cms签名，命令执行后hpm_file将是未签名的hpm裸包。
rootfs_output_tar_gz为生成的rootfs加压包，请使用tar -xvf rootfs_output_tar_gz解压得到rootfs_iBMC.img镜像文件，此文件为ext4分区格式的镜像文件，可以使用mount rootfs_iBMC.img rootfs命令将镜像挂载到rootfs目录，大小为376M + 4K，最后4K为防回退数据。
uboot_output_img为hpm包中的uboot镜像文件，大小为2M

CMakeLists.txt
```cmake
cmake_minimum_required(VERSION 3.16)
project(hpm_unpack)

AUX_SOURCE_DIRECTORY(. SRC)
ADD_EXECUTABLE(hpm_unpack ${SRC})

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTO REQUIRED libcrypto)

target_link_libraries(hpm_unpack PUBLIC libcrypto.a dl pthread m)
target_include_directories(hpm_unpack PUBLIC ${CRYPTO_INCLUDE_DIR})

INSTALL(TARGETS hpm_unpack RUNTIME DESTINATION ./)
```
build.sh
```shell
#!/bin/bash

set -e

mkdir .temp -p
cd .temp
cmake ..
make -j4
cp hpm_unpack ..
cd ..
rm .temp -rf
```

extracthpm.c
```
#include "extracthpm.h"
#include "extractv6.h"
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

// g++ -o hpm2cramfs extracthpm.c -lssl
// this software is dependent on openssl
FILE g_up_fil_fd;
FILE_CONFIG_S g_file_info[UPGRADE_MAX_COMPNENT_NUM];

static int check_hpm_md5(FILE *image_file) {
  int file_length = 0;
  char md5_get[MD5_SIZE + 1] = {0};
  char md5_calc[MD5_SIZE] = {0};

  /*1、首先得到这个文件指针所指的文件总大小*/
  /*point to the end, in order to get the file length*/
  fseek(image_file, 0L, SEEK_END);

  /*total file length*/
  file_length = ftell(image_file);

  /*2、根据HPM规范,最后16字节为MD5校验,取出来*/
  memset(md5_get, 0x00, sizeof(md5_get));

  /*point to the md5 position*/
  fseek(image_file, file_length - MD5_SIZE, SEEK_SET);

  fread(md5_get, 1, MD5_SIZE, image_file);

  /*4、比较2个Md5值,返回比较结果.相等返回TRUE,否则返回FALSE*/
  /* point to the head again */
  fseek(image_file, 0L, SEEK_SET);

  return 0;
}

static int validate_image_integrity(FILE *image_file) {
  int read_len = 0;
  HPM_FWUPG_IMAGE_HEADER_S *image_header = NULL;
  short oem_data_len = 0;
  char image_head_buff[UPGRADE_IMAGE_HEAD_SIZE] = {0};

  check_hpm_md5(image_file);
  /*2、校验文件头*/
  read_len = fread(image_head_buff, UPGRADE_IMAGE_HEAD_CNT,
                   UPGRADE_IMAGE_HEAD_SIZE, image_file);

  image_header = (HPM_FWUPG_IMAGE_HEADER_S *)image_head_buff;

  oem_data_len = CONS_IMAGE_OEM_LEN(image_header->oemDataLength[0],
                                    image_header->oemDataLength[1]);

  /* 从镜像文件中获取校验和--BTD */
  /*point to the checksum position*/
  fseek(image_file, sizeof(HPM_FWUPG_IMAGE_HEADER_S) + oem_data_len, SEEK_SET);

  return 0;
}

static int get_image_header(FILE *image_file, HPM_FWUPG_IMAGE_HEADER_S *image_head,
                     unsigned int image_head_len) {
  int ret_count = 0;
  char buff[sizeof(HPM_FWUPG_IMAGE_HEADER_S) + 1] = {0};

  fseek(image_file, 0L, SEEK_SET);

  ret_count = fread(buff, sizeof(HPM_FWUPG_IMAGE_HEADER_S),
                    UPGRADE_IMAGE_HEAD_CNT, image_file);

  /* 拷贝镜像头 */
  memmove(image_head, buff, sizeof(HPM_FWUPG_IMAGE_HEADER_S));

  return 0;
}

static int lookup_action_head_pos(FILE *image_handle) {
  HPM_FWUPG_IMAGE_HEADER_S *image_header = NULL;
  unsigned int oem_data_len = 0;

  /* 定义最小可用的空间大小，减少栈空间--BTD*/
  char buff[FILE_NAME_BUFFER_SIZE] = {0};

  get_image_header(image_handle, (HPM_FWUPG_IMAGE_HEADER_S *)buff,
                   sizeof(buff));

  image_header = (HPM_FWUPG_IMAGE_HEADER_S *)buff;

  oem_data_len = CONS_IMAGE_OEM_LEN(image_header->oemDataLength[0],
                                    image_header->oemDataLength[1]);

  /*point to the checksum position*/
  fseek(image_handle, oem_data_len + 1 /*代表一字节的校验和*/, SEEK_CUR);

  return 0;
}

static int parse_action_record(FILE *file_handle, FILE_CONFIG_S *file_info,
                        unsigned int compent_num) {
  unsigned int i = 0;
  int upgrade_file_offset = 0;
  unsigned int fw_length = 0;
  int ret_count;
  HPM_FWUPG_FIRMWARE_IMAGE_S *fw_image = NULL;
  char buff[FILE_NAME_BUFFER_SIZE] = {0};
  unsigned char count_comp_num = 0;
  char buff2[sizeof(HPM_FWUPG_ACTION_RECORD_S) + 1] = {0};
  int len = sizeof(HPM_FWUPG_ACTION_RECORD_S);

  lookup_action_head_pos(file_handle);

  fread(buff2, len, 1, file_handle);

  // fseek(file_handle, 0L, SEEK_SET);

  /**目前最多支持UPGRADE_MAX_COMPNENT_NUM个固件的升级**/
  for (i = 0; i < compent_num; i++) {
    if (count_comp_num > compent_num) {
      break;
    }

    fread(buff2, len, 1, file_handle);

    memset(buff, 0x00, sizeof(buff));

    ret_count = fread(buff, sizeof(HPM_FWUPG_FIRMWARE_IMAGE_S), 1, file_handle);

    fw_image = (HPM_FWUPG_FIRMWARE_IMAGE_S *)buff;

    fw_length = MAKE_DWORD(fw_image->length[3], fw_image->length[2],
                           fw_image->length[1], fw_image->length[0]);

    /* 实际升级文件的大小应该减去sizeof(HEAD_SERVICE_INFO_MY_S)字节是serviceinfo
     */
    file_info[count_comp_num].length =
        fw_length - sizeof(HEAD_SERVICE_INFO_MY_S); // 2.length

    /* 往后sizeof(HEAD_SERVICE_INFO_MY_S)字节是serviceinfo */
    fseek(file_handle, sizeof(HEAD_SERVICE_INFO_MY_S), SEEK_CUR);

    upgrade_file_offset = ftell(file_handle);

    file_info[count_comp_num].offset = upgrade_file_offset; // 3.offset

    printf("    %d: %d, %d\n", count_comp_num, file_info[count_comp_num].length,
           file_info[count_comp_num].offset);

    /* 此时已经指在实际的升级文件地址,将指针移至下一个action */
    fseek(file_handle, file_info[count_comp_num].length, SEEK_CUR);

    count_comp_num++;
  }

  return 0;
}

static int hex_char_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'a' && c <= 'f')
    return (c - 'a' + 10);
  else if (c >= 'A' && c <= 'F')
    return (c - 'A' + 10);
  return 0;
}
static int hex_to_decimal(const char *szHex, int len) {
  int result = 0;
  int i;
  for (i = 0; i < len; i++) {
    result += (int)pow((float)16, (int)len - i - 1) * hex_char_value(szHex[i]);
  }
  return result;
}

static int cms_read_size(FILE *image_file_handle, int *val) {
  char len_buf[8 + 1] = {0};
  int ret;

  //读出cms文件个数、id、大小等信息

  fread(len_buf, 1, 8, image_file_handle);

  // sscanf(len_buf, "%x", *val);
  *val = hex_to_decimal(len_buf, strlen(len_buf));

  return 0;
}

static int cms_clear_sign_file(const char *image_file, int cms_size, int file_size) {
  FILE *image_file_handle = NULL;
  char read_buff[10240] = {0};
  int read_len_total = 0;
  int read_len_once = 0;
  int remain_len = 0;
  int rw_cnt;

  //入参检查
  printf("Clear cms header of file %s.\n", image_file);
  image_file_handle = fopen(image_file, "r+");

  //从CMS文件信息后开始读取覆盖到文件头
  while (read_len_total != (file_size - cms_size)) {

    fseek(image_file_handle, cms_size + read_len_total, SEEK_SET);

    remain_len = file_size - cms_size - read_len_total;
    read_len_once = (10240 < remain_len) ? 10240 : remain_len;

    rw_cnt = fread(read_buff, 1, read_len_once, image_file_handle);

    fseek(image_file_handle, read_len_total, SEEK_SET);

    rw_cnt = fwrite(read_buff, 1, read_len_once, image_file_handle);

    read_len_total += rw_cnt;
  }

  fclose(image_file_handle);

  truncate(image_file, (off_t)read_len_total);
  return 0;
}

static int cut_cms_info(const char *file_name) {
  FILE *file_id = NULL;
  int file_num;
  int file1_len;
  int file2_len;
  int file3_len;
  int cms_size;
  int file_len;
  char header[8] = {0};

  file_id = fopen(file_name, "r+");
  if (!file_id) {
    printf("Open file %s failed, error: %s\n", file_name, strerror(errno));
    return -1;
  }
  fseek(file_id, 0L, SEEK_SET);
  fread(header, 8L, 1, file_id);
  if (memcmp(header, "PICMGFWU", 8) == 0) {
    fclose(file_id);
    return 0;
  }
  fseek(file_id, 0L, SEEK_END);
  file_len = ftell(file_id);

  fseek(file_id, 0L, SEEK_SET);
  cms_read_size(file_id, &file_num);
  cms_read_size(file_id, &file1_len);
  cms_read_size(file_id, &file1_len);
  cms_read_size(file_id, &file2_len);
  cms_read_size(file_id, &file2_len);
  cms_read_size(file_id, &file3_len);
  cms_read_size(file_id, &file3_len);

  cms_size = 7 * 4 * 2 + file1_len + file2_len + file3_len;

  fclose(file_id);

  cms_clear_sign_file(file_name, cms_size, file_len);

  return 0;
}

static int upgrade_prepare(const char *file_name, unsigned int *update_file_num,
                    void *file_info) {
  char path_info[FILE_NAME_BUFFER_SIZE] = {0};
  FILE *fil_fd = &g_up_fil_fd;

  /*********************** 4: ******************
  **升级镜像文件中升级动作字段解析,得到升级固件掩码,
  **得到升级固件开始偏移与长度
  **********************************************/
  fil_fd = fopen(file_name, "r");
  if (fil_fd <= 0) {
    printf("    fopen file %s fail\n", file_name);
  }
  // validate_image_integrity(fil_fd);
  char buff[FILE_NAME_BUFFER_SIZE] = {0};

  get_image_header(fil_fd, (HPM_FWUPG_IMAGE_HEADER_S *)buff, sizeof(buff));
  parse_action_record(fil_fd, (FILE_CONFIG_S *)file_info, 2);

  return 0;
}

static char pem_rsa[] = {
  0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50,
  0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
  0x4d, 0x49, 0x49, 0x45, 0x6f, 0x67, 0x49, 0x42, 0x41, 0x41, 0x4b, 0x43, 0x41, 0x51, 0x45, 0x41,
  0x77, 0x47, 0x39, 0x7a, 0x37, 0x7a, 0x79, 0x49, 0x4b, 0x47, 0x71, 0x38, 0x46, 0x43, 0x36, 0x63,
  0x55, 0x56, 0x45, 0x36, 0x52, 0x31, 0x36, 0x53, 0x32, 0x61, 0x52, 0x76, 0x6f, 0x75, 0x54, 0x5a,
  0x39, 0x6d, 0x6d, 0x4a, 0x71, 0x47, 0x46, 0x37, 0x46, 0x58, 0x2b, 0x68, 0x2f, 0x35, 0x35, 0x7a,
  0x0a, 0x55, 0x48, 0x72, 0x53, 0x4a, 0x73, 0x33, 0x65, 0x75, 0x62, 0x37, 0x65, 0x57, 0x38, 0x47,
  0x31, 0x31, 0x63, 0x79, 0x38, 0x53, 0x53, 0x6e, 0x53, 0x50, 0x44, 0x6a, 0x2f, 0x46, 0x45, 0x33,
  0x52, 0x75, 0x57, 0x37, 0x78, 0x39, 0x62, 0x77, 0x58, 0x62, 0x36, 0x43, 0x64, 0x39, 0x77, 0x65,
  0x6c, 0x6d, 0x37, 0x36, 0x4b, 0x39, 0x57, 0x6d, 0x33, 0x6f, 0x62, 0x6e, 0x52, 0x5a, 0x48, 0x5a,
  0x68, 0x0a, 0x35, 0x6b, 0x66, 0x32, 0x5a, 0x53, 0x6e, 0x70, 0x4c, 0x71, 0x41, 0x32, 0x67, 0x43,
  0x4f, 0x43, 0x4a, 0x47, 0x49, 0x36, 0x36, 0x6c, 0x4e, 0x55, 0x42, 0x44, 0x5a, 0x70, 0x71, 0x75,
  0x75, 0x35, 0x79, 0x6d, 0x2b, 0x49, 0x7a, 0x30, 0x64, 0x35, 0x4a, 0x57, 0x6d, 0x59, 0x6b, 0x37,
  0x70, 0x75, 0x55, 0x31, 0x39, 0x6f, 0x37, 0x47, 0x44, 0x55, 0x51, 0x76, 0x56, 0x2b, 0x39, 0x6f,
  0x74, 0x44, 0x0a, 0x71, 0x32, 0x47, 0x55, 0x77, 0x33, 0x6b, 0x71, 0x4f, 0x79, 0x59, 0x70, 0x49,
  0x65, 0x67, 0x33, 0x42, 0x44, 0x61, 0x76, 0x6e, 0x58, 0x77, 0x4a, 0x71, 0x53, 0x74, 0x6b, 0x72,
  0x44, 0x70, 0x44, 0x42, 0x35, 0x6a, 0x6f, 0x31, 0x4d, 0x68, 0x58, 0x78, 0x54, 0x45, 0x6e, 0x74,
  0x5a, 0x57, 0x4a, 0x46, 0x4c, 0x50, 0x41, 0x78, 0x36, 0x57, 0x63, 0x74, 0x51, 0x42, 0x6f, 0x63,
  0x4e, 0x51, 0x64, 0x0a, 0x53, 0x6c, 0x58, 0x39, 0x38, 0x62, 0x79, 0x36, 0x45, 0x5a, 0x64, 0x4c,
  0x5a, 0x2b, 0x2f, 0x4c, 0x33, 0x4b, 0x73, 0x6b, 0x34, 0x6d, 0x52, 0x57, 0x41, 0x45, 0x73, 0x44,
  0x4a, 0x47, 0x32, 0x58, 0x69, 0x39, 0x53, 0x39, 0x79, 0x49, 0x6a, 0x57, 0x63, 0x75, 0x73, 0x54,
  0x76, 0x32, 0x4a, 0x6b, 0x41, 0x45, 0x70, 0x71, 0x38, 0x59, 0x32, 0x5a, 0x57, 0x6a, 0x56, 0x6d,
  0x35, 0x69, 0x4d, 0x66, 0x0a, 0x77, 0x39, 0x4d, 0x59, 0x71, 0x36, 0x2f, 0x68, 0x79, 0x76, 0x54,
  0x55, 0x51, 0x30, 0x4c, 0x4a, 0x68, 0x43, 0x49, 0x6a, 0x39, 0x2b, 0x31, 0x73, 0x76, 0x70, 0x49,
  0x5a, 0x50, 0x46, 0x4c, 0x6a, 0x6e, 0x4a, 0x72, 0x2b, 0x4a, 0x51, 0x49, 0x44, 0x41, 0x51, 0x41,
  0x42, 0x41, 0x6f, 0x49, 0x42, 0x41, 0x48, 0x36, 0x69, 0x47, 0x55, 0x48, 0x4b, 0x72, 0x4c, 0x4d,
  0x6b, 0x49, 0x65, 0x61, 0x4b, 0x0a, 0x45, 0x62, 0x58, 0x31, 0x5a, 0x51, 0x75, 0x49, 0x4d, 0x63,
  0x7a, 0x6c, 0x52, 0x38, 0x32, 0x44, 0x47, 0x65, 0x66, 0x73, 0x35, 0x58, 0x69, 0x58, 0x78, 0x58,
  0x36, 0x4e, 0x51, 0x68, 0x62, 0x4c, 0x74, 0x34, 0x69, 0x7a, 0x65, 0x6b, 0x32, 0x73, 0x31, 0x69,
  0x2b, 0x58, 0x61, 0x67, 0x34, 0x70, 0x75, 0x44, 0x59, 0x63, 0x68, 0x35, 0x38, 0x42, 0x31, 0x57,
  0x5a, 0x70, 0x2f, 0x33, 0x6e, 0x6d, 0x0a, 0x42, 0x2b, 0x67, 0x6d, 0x47, 0x54, 0x57, 0x6a, 0x64,
  0x43, 0x79, 0x79, 0x48, 0x71, 0x46, 0x73, 0x4e, 0x38, 0x2f, 0x34, 0x6f, 0x4d, 0x73, 0x45, 0x71,
  0x61, 0x48, 0x55, 0x66, 0x50, 0x58, 0x47, 0x62, 0x59, 0x41, 0x7a, 0x78, 0x50, 0x49, 0x6e, 0x6c,
  0x56, 0x70, 0x6f, 0x64, 0x64, 0x54, 0x33, 0x43, 0x50, 0x4a, 0x57, 0x62, 0x66, 0x79, 0x37, 0x6e,
  0x79, 0x4d, 0x79, 0x68, 0x33, 0x44, 0x42, 0x0a, 0x74, 0x4c, 0x36, 0x42, 0x6a, 0x52, 0x38, 0x53,
  0x49, 0x71, 0x65, 0x37, 0x43, 0x48, 0x76, 0x57, 0x69, 0x44, 0x6c, 0x33, 0x4a, 0x4c, 0x33, 0x41,
  0x72, 0x6f, 0x33, 0x73, 0x69, 0x48, 0x71, 0x65, 0x76, 0x56, 0x42, 0x42, 0x36, 0x55, 0x75, 0x79,
  0x4c, 0x73, 0x65, 0x51, 0x4a, 0x31, 0x46, 0x54, 0x58, 0x7a, 0x69, 0x34, 0x76, 0x44, 0x36, 0x43,
  0x70, 0x50, 0x48, 0x59, 0x67, 0x56, 0x4e, 0x34, 0x0a, 0x4c, 0x69, 0x58, 0x38, 0x4c, 0x61, 0x56,
  0x4c, 0x77, 0x4c, 0x58, 0x30, 0x52, 0x56, 0x50, 0x45, 0x30, 0x58, 0x76, 0x42, 0x54, 0x34, 0x31,
  0x56, 0x59, 0x38, 0x47, 0x71, 0x48, 0x62, 0x76, 0x4c, 0x30, 0x43, 0x33, 0x53, 0x36, 0x6a, 0x4f,
  0x4f, 0x77, 0x61, 0x72, 0x2b, 0x71, 0x61, 0x58, 0x56, 0x70, 0x52, 0x31, 0x65, 0x55, 0x36, 0x38,
  0x79, 0x70, 0x30, 0x31, 0x46, 0x53, 0x4c, 0x79, 0x48, 0x0a, 0x73, 0x47, 0x48, 0x2b, 0x66, 0x63,
  0x43, 0x44, 0x6d, 0x61, 0x79, 0x45, 0x4b, 0x65, 0x6f, 0x72, 0x4c, 0x77, 0x46, 0x54, 0x67, 0x63,
  0x39, 0x69, 0x6e, 0x4a, 0x7a, 0x73, 0x2f, 0x77, 0x74, 0x7a, 0x42, 0x6c, 0x65, 0x51, 0x54, 0x6a,
  0x78, 0x44, 0x70, 0x49, 0x32, 0x70, 0x36, 0x70, 0x50, 0x61, 0x73, 0x6e, 0x6a, 0x39, 0x41, 0x2f,
  0x6c, 0x58, 0x67, 0x4e, 0x48, 0x69, 0x33, 0x78, 0x6b, 0x44, 0x0a, 0x65, 0x2f, 0x4e, 0x4d, 0x79,
  0x42, 0x55, 0x43, 0x67, 0x59, 0x45, 0x41, 0x38, 0x44, 0x62, 0x36, 0x55, 0x53, 0x64, 0x41, 0x5a,
  0x65, 0x6e, 0x39, 0x44, 0x70, 0x4f, 0x78, 0x55, 0x68, 0x43, 0x77, 0x2f, 0x58, 0x69, 0x61, 0x61,
  0x77, 0x35, 0x55, 0x72, 0x5a, 0x66, 0x77, 0x78, 0x6a, 0x78, 0x64, 0x61, 0x43, 0x50, 0x4f, 0x36,
  0x68, 0x55, 0x65, 0x4d, 0x2f, 0x4d, 0x55, 0x33, 0x69, 0x61, 0x6a, 0x0a, 0x66, 0x2b, 0x5a, 0x6e,
  0x39, 0x2f, 0x55, 0x4d, 0x4a, 0x53, 0x6d, 0x32, 0x72, 0x33, 0x2f, 0x52, 0x43, 0x32, 0x50, 0x6c,
  0x53, 0x54, 0x69, 0x30, 0x48, 0x4c, 0x67, 0x46, 0x55, 0x48, 0x47, 0x4d, 0x65, 0x71, 0x70, 0x76,
  0x70, 0x59, 0x2b, 0x68, 0x76, 0x45, 0x43, 0x56, 0x2b, 0x2b, 0x71, 0x2f, 0x2b, 0x67, 0x63, 0x54,
  0x45, 0x75, 0x31, 0x39, 0x78, 0x2b, 0x62, 0x50, 0x78, 0x59, 0x51, 0x7a, 0x0a, 0x66, 0x36, 0x4f,
  0x5a, 0x77, 0x71, 0x4a, 0x72, 0x6f, 0x48, 0x45, 0x6d, 0x54, 0x71, 0x34, 0x46, 0x4a, 0x44, 0x66,
  0x59, 0x79, 0x30, 0x57, 0x57, 0x6c, 0x6e, 0x69, 0x4f, 0x73, 0x43, 0x58, 0x63, 0x66, 0x62, 0x6e,
  0x71, 0x2f, 0x49, 0x67, 0x77, 0x74, 0x36, 0x57, 0x63, 0x6d, 0x6c, 0x49, 0x2b, 0x45, 0x6c, 0x67,
  0x51, 0x70, 0x34, 0x38, 0x43, 0x67, 0x59, 0x45, 0x41, 0x7a, 0x52, 0x53, 0x30, 0x0a, 0x54, 0x75,
  0x64, 0x44, 0x77, 0x7a, 0x6f, 0x67, 0x45, 0x58, 0x55, 0x70, 0x56, 0x46, 0x72, 0x4a, 0x72, 0x65,
  0x7a, 0x58, 0x64, 0x68, 0x78, 0x78, 0x4b, 0x69, 0x53, 0x62, 0x63, 0x66, 0x69, 0x4b, 0x67, 0x66,
  0x33, 0x76, 0x57, 0x37, 0x50, 0x30, 0x33, 0x36, 0x4c, 0x61, 0x76, 0x61, 0x64, 0x52, 0x54, 0x2f,
  0x6e, 0x41, 0x6a, 0x67, 0x58, 0x76, 0x47, 0x54, 0x6f, 0x30, 0x48, 0x50, 0x6d, 0x47, 0x0a, 0x33,
  0x7a, 0x36, 0x76, 0x41, 0x6e, 0x55, 0x50, 0x72, 0x74, 0x74, 0x44, 0x55, 0x7a, 0x69, 0x6a, 0x4c,
  0x72, 0x50, 0x4a, 0x75, 0x50, 0x6e, 0x69, 0x6b, 0x41, 0x2f, 0x54, 0x77, 0x37, 0x71, 0x49, 0x6a,
  0x54, 0x7a, 0x32, 0x50, 0x4e, 0x7a, 0x42, 0x72, 0x2f, 0x48, 0x38, 0x68, 0x2f, 0x48, 0x4c, 0x33,
  0x67, 0x79, 0x54, 0x53, 0x70, 0x33, 0x61, 0x56, 0x4d, 0x30, 0x2b, 0x30, 0x65, 0x4d, 0x70, 0x0a,
  0x53, 0x72, 0x59, 0x4e, 0x7a, 0x42, 0x59, 0x6f, 0x39, 0x64, 0x59, 0x61, 0x61, 0x36, 0x73, 0x51,
  0x78, 0x4e, 0x4e, 0x76, 0x34, 0x4e, 0x61, 0x49, 0x66, 0x2b, 0x31, 0x45, 0x4a, 0x7a, 0x6b, 0x69,
  0x42, 0x2f, 0x61, 0x43, 0x42, 0x51, 0x73, 0x43, 0x67, 0x59, 0x41, 0x30, 0x4c, 0x51, 0x7a, 0x6a,
  0x38, 0x61, 0x32, 0x6f, 0x4e, 0x56, 0x48, 0x56, 0x42, 0x37, 0x6c, 0x39, 0x52, 0x4d, 0x6a, 0x63,
  0x0a, 0x31, 0x59, 0x52, 0x63, 0x2b, 0x6f, 0x6a, 0x6b, 0x42, 0x39, 0x75, 0x78, 0x67, 0x30, 0x30,
  0x61, 0x6f, 0x4b, 0x53, 0x42, 0x37, 0x63, 0x4a, 0x59, 0x73, 0x46, 0x54, 0x35, 0x42, 0x39, 0x56,
  0x39, 0x6f, 0x33, 0x4d, 0x7a, 0x78, 0x5a, 0x4d, 0x30, 0x77, 0x30, 0x47, 0x2b, 0x44, 0x76, 0x6f,
  0x2b, 0x43, 0x68, 0x32, 0x30, 0x63, 0x4d, 0x2b, 0x57, 0x61, 0x56, 0x59, 0x6d, 0x4b, 0x66, 0x50,
  0x45, 0x0a, 0x64, 0x52, 0x36, 0x35, 0x44, 0x47, 0x43, 0x70, 0x2f, 0x6a, 0x46, 0x56, 0x76, 0x61,
  0x43, 0x6a, 0x55, 0x30, 0x51, 0x4f, 0x57, 0x57, 0x31, 0x33, 0x72, 0x53, 0x65, 0x32, 0x46, 0x45,
  0x67, 0x48, 0x55, 0x6d, 0x62, 0x45, 0x67, 0x76, 0x6a, 0x7a, 0x71, 0x59, 0x41, 0x54, 0x6d, 0x50,
  0x4c, 0x65, 0x38, 0x67, 0x35, 0x78, 0x34, 0x4a, 0x53, 0x62, 0x37, 0x47, 0x57, 0x35, 0x31, 0x77,
  0x39, 0x30, 0x0a, 0x63, 0x35, 0x79, 0x5a, 0x36, 0x34, 0x38, 0x42, 0x5a, 0x4d, 0x53, 0x47, 0x4e,
  0x4a, 0x54, 0x73, 0x38, 0x52, 0x6e, 0x30, 0x2b, 0x77, 0x4b, 0x42, 0x67, 0x42, 0x41, 0x32, 0x61,
  0x38, 0x36, 0x31, 0x44, 0x37, 0x46, 0x57, 0x58, 0x67, 0x53, 0x6a, 0x53, 0x34, 0x49, 0x6b, 0x72,
  0x7a, 0x37, 0x31, 0x73, 0x30, 0x37, 0x65, 0x44, 0x73, 0x41, 0x7a, 0x4a, 0x71, 0x72, 0x4b, 0x36,
  0x45, 0x42, 0x41, 0x0a, 0x6a, 0x2f, 0x53, 0x69, 0x39, 0x46, 0x2f, 0x64, 0x6f, 0x77, 0x64, 0x4e,
  0x4f, 0x2b, 0x74, 0x6a, 0x70, 0x69, 0x70, 0x55, 0x49, 0x38, 0x50, 0x4e, 0x79, 0x79, 0x4c, 0x6a,
  0x51, 0x78, 0x74, 0x51, 0x2f, 0x45, 0x72, 0x6f, 0x63, 0x44, 0x58, 0x31, 0x6c, 0x59, 0x76, 0x31,
  0x74, 0x55, 0x6a, 0x53, 0x34, 0x38, 0x61, 0x67, 0x30, 0x70, 0x31, 0x71, 0x38, 0x75, 0x58, 0x4e,
  0x55, 0x46, 0x42, 0x43, 0x0a, 0x47, 0x6f, 0x46, 0x54, 0x50, 0x6d, 0x69, 0x6e, 0x61, 0x37, 0x78,
  0x66, 0x6a, 0x43, 0x74, 0x67, 0x75, 0x53, 0x41, 0x7a, 0x2f, 0x48, 0x65, 0x70, 0x78, 0x69, 0x61,
  0x58, 0x6d, 0x38, 0x4d, 0x52, 0x51, 0x32, 0x50, 0x33, 0x2b, 0x49, 0x4c, 0x2b, 0x79, 0x78, 0x58,
  0x70, 0x37, 0x79, 0x68, 0x77, 0x51, 0x71, 0x37, 0x32, 0x70, 0x74, 0x48, 0x65, 0x4d, 0x76, 0x34,
  0x61, 0x30, 0x53, 0x72, 0x70, 0x0a, 0x2f, 0x50, 0x74, 0x6a, 0x41, 0x6f, 0x47, 0x41, 0x4b, 0x4b,
  0x58, 0x54, 0x4e, 0x65, 0x6f, 0x66, 0x4b, 0x54, 0x61, 0x6a, 0x54, 0x6c, 0x4d, 0x66, 0x31, 0x50,
  0x6f, 0x33, 0x71, 0x48, 0x66, 0x4e, 0x63, 0x51, 0x42, 0x76, 0x41, 0x48, 0x34, 0x74, 0x46, 0x71,
  0x63, 0x44, 0x6c, 0x66, 0x2b, 0x57, 0x6f, 0x51, 0x56, 0x65, 0x73, 0x2f, 0x36, 0x53, 0x65, 0x4c,
  0x41, 0x64, 0x74, 0x56, 0x62, 0x46, 0x0a, 0x47, 0x59, 0x54, 0x32, 0x7a, 0x62, 0x44, 0x45, 0x70,
  0x56, 0x6b, 0x35, 0x69, 0x5a, 0x43, 0x76, 0x52, 0x31, 0x4f, 0x74, 0x43, 0x57, 0x38, 0x79, 0x6e,
  0x68, 0x65, 0x74, 0x46, 0x34, 0x6a, 0x34, 0x66, 0x65, 0x51, 0x47, 0x54, 0x42, 0x4d, 0x72, 0x65,
  0x48, 0x31, 0x55, 0x43, 0x64, 0x32, 0x4b, 0x6b, 0x39, 0x77, 0x62, 0x75, 0x34, 0x38, 0x2f, 0x32,
  0x79, 0x46, 0x70, 0x64, 0x56, 0x38, 0x6d, 0x0a, 0x75, 0x6d, 0x58, 0x46, 0x6f, 0x56, 0x64, 0x4b,
  0x67, 0x53, 0x34, 0x69, 0x4a, 0x79, 0x45, 0x75, 0x58, 0x4b, 0x68, 0x41, 0x2b, 0x69, 0x67, 0x6f,
  0x4f, 0x61, 0x41, 0x64, 0x7a, 0x42, 0x30, 0x63, 0x62, 0x39, 0x74, 0x4d, 0x36, 0x38, 0x6f, 0x58,
  0x59, 0x77, 0x67, 0x46, 0x77, 0x76, 0x37, 0x37, 0x76, 0x49, 0x6b, 0x3d, 0x0a, 0x2d, 0x2d, 0x2d,
  0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54,
  0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
};

static int RSA_Decrypt(unsigned char *m, unsigned char *out, unsigned int outlen) {
  char *p_de = NULL;
  RSA *p_rsa = NULL;
  unsigned int rsa_len = 0;
  int ret = -1;

  BIO *bio = BIO_new_mem_buf((void*)pem_rsa, sizeof(pem_rsa));

  p_rsa = (RSA *)PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  if (p_rsa) {
    rsa_len = RSA_size(p_rsa);
    p_de = (char *)malloc(rsa_len + 1);
    memset(p_de, 0, rsa_len + 1);
    if ((ret = RSA_private_decrypt(256, (unsigned char *)m,
                                    (unsigned char *)p_de, p_rsa,
                                    RSA_PKCS1_OAEP_PADDING)) < 0) {
      ret =
          RSA_private_decrypt(256, (unsigned char *)m, (unsigned char *)p_de,
                              p_rsa, RSA_PKCS1_PADDING);
    }
    if (ret >= 0) {
      if (outlen > (rsa_len + 1)) {
        outlen = rsa_len;
      }
      memmove(out, p_de, outlen);
    } else {
      ret = -1;
    }
  } else {
    ret = -1;
  }
  BIO_free(bio);

  if (p_rsa) {
    RSA_free(p_rsa);
    p_rsa = NULL;
  }
  if (p_de) {
    free(p_de);
    p_de = NULL;
  }
  return ret;
}

static int pme_get_aes_key(char *out, size_t *out_len, const char *in, size_t in_len) {
  unsigned char *in_buf = NULL;
  int ret = -1;
  unsigned char temp_out[16] = {0};

  in_buf = (unsigned char *)malloc(in_len);
  memcpy(in_buf, in, in_len);
  if (in_buf) {
    int ret = RSA_Decrypt(in_buf, (unsigned char *)temp_out, AES_BLOCK_SIZE);
    if (ret != 0) {
      return ret;
    }
    *out_len = AES_BLOCK_SIZE;
    ret = 0;
  }

  memcpy(out, temp_out, 16);

  if (in_buf) {
    free(in_buf);
    // in_buf = NULL;-wlint 438
  }
  return ret;
}

static int get_decrypt_aes_key(int file_handle, long offset_pos, char *key,
                        int *key_len) {
  char data_key[UP_DECRYPT_HEADER_SIZE] = {0};

  lseek(file_handle, offset_pos, SEEK_SET);

  printf("    Read rsa data, offset: %ld\n", offset_pos);
  read(file_handle, data_key, UP_DECRYPT_HEADER_SIZE);

  return pme_get_aes_key(key, (size_t *)key_len, data_key, UP_DECRYPT_HEADER_SIZE);
}

static int pme_decrypt_data(char *out, size_t *out_len, const char *in, size_t in_len,
                     const char *key) {
  int ret = -1;
  size_t dec_len = 0;
  char IV[AES_BLOCK_SIZE] = {};
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  memmove(IV, in, AES_BLOCK_SIZE); //璇诲彇IV
  EVP_CIPHER_CTX_init(ctx);
  EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (const unsigned char *)key,
                     (const unsigned char *)IV);

  ret = EVP_DecryptUpdate(ctx, (unsigned char *)out, (int *)&dec_len,
                          (const unsigned char *)(in + AES_BLOCK_SIZE),
                          (int)(in_len - AES_BLOCK_SIZE));

  *out_len = dec_len;
  ret = EVP_DecryptFinal_ex(ctx, (unsigned char *)(out + *out_len),
                            (int *)&dec_len); //澶勭悊濉厖

  *out_len += dec_len;

  EVP_CIPHER_CTX_cleanup(ctx);

  return 0;
}

int get_decrypt_data_from_hpm(unsigned char *out_buf, unsigned int *out_len,
                              const unsigned char *in_buf, unsigned int in_len,
                              char *key) {

  pme_decrypt_data((char *)out_buf, (size_t *)out_len, (const char *)in_buf,
                   (size_t)in_len, (const char *)key);

  if ((in_len > (*out_len + 32)) || (in_len < (*out_len + 17))) {
    printf("    decrypt error\n");
    return -1;
  }

  return 0;
}

static int start_upgrade(const char *file_name, const char *rootfs_name) {
  int result = 0;
  int dst_fd;
  unsigned char dest_buf[DECRYPT_BUFSIZE] = {0};
  int up_fil_fd;
  char decrypt_key[UP_DECRYPT_KEY_SIZE] = {0};
  int key_len = 0;
  long lenth = 0;
  long size = 0;
  long written = 0;
  unsigned char g_mtd_temp_src[DECRYPT_BUFSIZE] = {0};
  unsigned char g_mtd_temp_dest[DECRYPT_BUFSIZE];
  unsigned int data_len = 0;
  int i;
  int index;
  unsigned int file_num;
  FILE_CONFIG_S *file_info = g_file_info;

  int total_len = 0;

  memset(file_info, 0, sizeof(g_file_info));

  printf("    %s:%d\n", __FUNCTION__, __LINE__);
  upgrade_prepare(file_name, &file_num, (void *)g_file_info);

  for (index = 1; index < 2; index++) {
    lenth = file_info[index].length - UP_DECRYPT_HEADER_SIZE;
    printf("    lenth: %ld\n", lenth);

    if (index != 1)
      continue;
    printf("Start read %s\n", rootfs_name);
    dst_fd = open(rootfs_name, O_WRONLY | O_CREAT,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    up_fil_fd = open(file_name, O_RDONLY);

    printf("    index: %d, offset: %d\n", index, file_info[index].offset);
    int ret = get_decrypt_aes_key(up_fil_fd, file_info[index].offset, decrypt_key,
                        &key_len);
    if (ret != 0) {
      return ret;
    }
    int index_j;
    printf("    ");
    for (index_j = 0; index_j < 16; index_j++) {
      printf("%2x ", (unsigned char)decrypt_key[index_j]);
    }
    printf("\n");

    size = lenth;
    i = DECRYPT_BUFSIZE;
    written = 0;

    while (size > 0) {
      if (size < DECRYPT_BUFSIZE) {
        i = size;
      }
      sleep(0.01);
      memset(g_mtd_temp_src, 0, sizeof(g_mtd_temp_src));
      read(up_fil_fd, g_mtd_temp_src, i);
      memset(g_mtd_temp_dest, 0, sizeof(g_mtd_temp_dest));
      get_decrypt_data_from_hpm(g_mtd_temp_dest, &data_len, g_mtd_temp_src, i,
                                decrypt_key);
      write(dst_fd, g_mtd_temp_dest, data_len);

      total_len += data_len;

      written += i;
      size -= i;
    }
    close(dst_fd);
    close(up_fil_fd);
    return 0;
  }
  return -1;
}

static void extract_bin(const char *file_name, const char *out_file, int offset,
                 int size) {
  FILE *bin_file = NULL;
  unsigned char buff[512] = {0};
  FILE *appfs = NULL;
  int countbyte = 0;
  int end_pos = 0;
  int len = 0;
  int index;

  bin_file = fopen(file_name, "rb");
  do {
    memset(buff, 0, 512);
    fseek(bin_file, offset + size - 1, SEEK_SET);
    fread(buff, 1, 512, bin_file);
    size -= 512;
  } while (buff[0] == 255);
  for (index = 511; index >= 0; index--) {
    if (buff[index] != 255) {
      break;
    }
  }
  size = size + 512 + index;

  fseek(bin_file, offset, SEEK_SET);
  appfs = fopen(out_file, "w+");
  countbyte = 0;
  len = 512;
  while (countbyte < size) {
    memset(buff, 0, 512);
    if (countbyte + 512 > size) {
      len = size - countbyte;
    }
    fread(buff, 1, len, bin_file);
    fwrite(buff, 1, len, appfs);
    countbyte += len;
  }
  fclose(bin_file);
  fclose(appfs);
}

int main(int argc, char *argv[]) {
  if (argc < 2 || strcmp(argv[1], "-h") == 0 ||
      strcmp(argv[1], "--help") == 0) {
    printf("Paramater error, usage: %s hpm_file <rootfs_output_tar_gz> "
           "<uboot_output_img>\n",
           argv[0]);
    return -1;
  }
  const char *hpm_file = argv[1];
  const char *rootfs_img = "rootfs.tar.gz";
  const char *uboot_bin = "uboot.bin";
  if (argc >= 3) {
    rootfs_img = argv[2];
  }
  if (argc >= 4) {
    uboot_bin = argv[3];
  }
  printf("begin extract: %s\n", hpm_file);
  if (cut_cms_info(hpm_file) != 0) {
    return -1;
  }
  printf("mock upgrade: %s\n", hpm_file);
  const char *hpm_bin = "image.bin";
  if (start_upgrade(hpm_file, hpm_bin) != 0) {
    return -1;
  }
  if (extractv6(hpm_bin, rootfs_img, uboot_bin) != 0) {
    return -1;
  }
  return 0;
}
```
extracthpm.h
```c
#define UP_DECRYPT_HEADER_SIZE      (256)
#define UP_DECRYPT_DATA_SIZE_MAX    (32)
#define UP_DECRYPT_DATA_SIZE_MIN    (17)
#define UP_DECRYPT_KEY_SIZE     (16)
#define DECRYPT_BUFSIZE         (10 * 1024 + UP_DECRYPT_DATA_SIZE_MAX)  /* size of read/write buffer */
#define FILE_NAME_BUFFER_SIZE   (256)
#define MAX_FILEPATH_LENGTH (256)

#define UP_DECRYPT_HEADER_SIZE      (256)
#define AES_BLOCK_SIZE 16

#define MAKE_DWORD(a, b, c, d) (unsigned int)((((unsigned int)((unsigned char)(a))) << 24) | (((unsigned int)((unsigned char)(b))) << 16) | (((unsigned int)((unsigned char)(c))) << 8) | ((unsigned char)(d)))

#define HPMFWUPG_FIRM_REVISION_LENGTH   (6)
#define HPMFWUPG_DESCRIPTION_LENGTH     (21)
#define HPMFWUPG_FIRMWARE_SIZE_LENGTH   (4)
#define HPMFWUPG_COMP_REVISION_LENGTH   (2)

#define HPMFWUPG_TIMEOUT_LENGTH         (1)

#define CONS_IMAGE_OEM_LEN(low,high)              ((low) + (((short)high) << 8))

#define UPGRADE_IMAGE_HEAD_CNT      (1)

#define MAX_FILE_PATH_HPM       (24)
#define AUX_INFO_SIZE           (256)
#define MAX_BANK                (8)

#define MD5_SIZE                    (16)

typedef struct tag_SERVICE_INFO_MY
{
    unsigned int BankOffset;
    unsigned int BankLength;
    unsigned char file_path[MAX_FILE_PATH_HPM];
} SERVICE_INFO_MY_S;

typedef struct tag_HEAD_SERVICE_INFO_MY
{
    //_UL Length;
    //guint8 HeadFlag;
    union
    {
        unsigned char data[512]; //����Ҫ����RecordHead�Ĵ�С��22. ��Ϊ�п��ܽ���һ֡���ݿ���������
        struct
        {
            unsigned char AuxInfo[AUX_INFO_SIZE]; //����Ԥ��32�ֽ�����ΪҪ��SeviceInfo��ǰ���crc,�����汾�ŵ���Ϣ
            SERVICE_INFO_MY_S SeviceInfo[MAX_BANK];
        } RecordHead;
    } Info;
} HEAD_SERVICE_INFO_MY_S;

// ������������������Ľṹ
typedef struct tag_UPGRADE_PARAM
{
    int  up_src;   /* ����������Դͷ��OEM/IPMI */
    int  fruid;    /*�����̼�����Ӧ��FRUID*/
    unsigned int offset;   /*��Ҫ�����������������ļ��е�ƫ��λ��*/
    int length;    /*��Ҫ�����������������ļ��еĳ���*/
    int  component_id; /*�����̼�ID*/
    char upgrade_file_name[FILE_NAME_BUFFER_SIZE]; /*��Ҫ�������ļ�����*/
}UPGRADE_PARAM_S;

typedef struct tag_FILE_CONFIG
{
    int component_id;                     /*�̼���*/
    int fru_id;                           /*FRU id*/
    int board_id;                         /*����ID*/
    char file_path[MAX_FILEPATH_LENGTH];   /*�����̼���Ӧ�Ķ�̬���ӿ�����--BTD*/
    int offset;                           /*�����̼��������ļ��е�ƫ��λ��*/
    int length;                          /*�����̼��������ļ��еĴ�С*/    
    int dll_len;                         /*��̬���ӿ��������ļ��еĳ���--BTD��������������Ӵ˳���*/
} FILE_CONFIG_S;

typedef struct tag_HPM_FWUPG_FIRMWARE_IMAGE
{
    unsigned char version[HPMFWUPG_FIRM_REVISION_LENGTH]; /* Firmware version */
    char  desc[HPMFWUPG_DESCRIPTION_LENGTH];      /* Firmware description string */
    unsigned char length[HPMFWUPG_FIRMWARE_SIZE_LENGTH];  /* Firmware length */

    /*
    guint8 firmwareImageData[m];
     */
} HPM_FWUPG_FIRMWARE_IMAGE_S;

#define HPMFWUPG_HEADER_SIGNATURE_LENGTH (8)
#define HPMFWUPG_MANUFATURER_ID_LENGTH  (3)
#define HPMFWUPG_PRODUCT_ID_LENGTH      (2)
#define HPMFWUPG_TIME_LENGTH            (4)

#define UPGRADE_MAX_COMPNENT_NUM    (32)//(128)
#define UPGRADE_GROUP_MEM_CNT       (8)
typedef struct tag_HPM_FWUPG_COMPONENT_BITMASK
{
    union
    {
        unsigned char byte;
        struct
        {
#ifdef BD_BIG_ENDIAN
            unsigned char component7 : 1;
            unsigned char component6 : 1;
            unsigned char component5 : 1;
            unsigned char component4 : 1;
            unsigned char component3 : 1;
            unsigned char component2 : 1;
            unsigned char component1 : 1;
            unsigned char component0 : 1;
#else
            unsigned char component0 : 1;
            unsigned char component1 : 1;
            unsigned char component2 : 1;
            unsigned char component3 : 1;
            unsigned char component4 : 1;
            unsigned char component5 : 1;
            unsigned char component6 : 1;
            unsigned char component7 : 1;
#endif
        } bitField;
    } ComponentBits[UPGRADE_MAX_COMPNENT_NUM / UPGRADE_GROUP_MEM_CNT];
} HPM_FWUPG_COMPONENT_BITMASK_S;
typedef struct tag_HPM_FWUPG_IMAGE_HEADER
{
    char  signature[HPMFWUPG_HEADER_SIGNATURE_LENGTH];
    unsigned char formatVersion;
    unsigned char deviceId;
    unsigned char manId[HPMFWUPG_MANUFATURER_ID_LENGTH];  /* Manufacturer ID */
    unsigned char prodId[HPMFWUPG_PRODUCT_ID_LENGTH];     /* Product ID */
    unsigned char time[HPMFWUPG_TIME_LENGTH];
    union
    {
        struct
        {
/*#ifdef BD_BIG_ENDIAN
            unsigned char reserved        : 4;
            unsigned char svcAffected     : 1;
            unsigned char manualRollback  : 1;
            unsigned char autoRollback    : 1;
            unsigned char imageSelfTest   : 1;
#else*/
            unsigned char imageSelfTest   : 1;
            unsigned char autoRollback    : 1;
            unsigned char manualRollback  : 1;
            unsigned char svcAffected     : 1;
            unsigned char reserved        : 4;
//#endif
        } bitField;
        unsigned char byte;
    } imageCapabilities;
    HPM_FWUPG_COMPONENT_BITMASK_S components;/* ��ǰû���õ� */
    unsigned char  selfTestTimeout[HPMFWUPG_TIMEOUT_LENGTH];
    unsigned char  rollbackTimeout[HPMFWUPG_TIMEOUT_LENGTH];
    unsigned char  inaccessTimeout[HPMFWUPG_TIMEOUT_LENGTH];
    unsigned char  compRevision[HPMFWUPG_COMP_REVISION_LENGTH]; /* Earliest Compatible Revision */
    unsigned char  firmRevision[HPMFWUPG_FIRM_REVISION_LENGTH];
    unsigned char  oemDataLength[2];

    /*
    guint8  oemDataDescriptorList[n];
    guint8  headerChecksum;
     */
} HPM_FWUPG_IMAGE_HEADER_S;

/* Upgrade action record */
typedef struct tag_HPM_FWUPG_ACTION_RECORD
{
    unsigned char actionType;
    HPM_FWUPG_COMPONENT_BITMASK_S components;
    unsigned char headerChecksum;

    /*
    struct HpmfwupgFirmwareImage fwImage; -- optional, only need in upgrade action record
     */
} HPM_FWUPG_ACTION_RECORD_S;

#define UPGRADE_IMAGE_HEAD_SIZE     (sizeof(HPM_FWUPG_IMAGE_HEADER_S))
```
extractv6.c
```c
#include "extractv6.h"
#include "extracthpm.h"
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
write_upgrade_data_to_flash -> rootfs_component_handle ->
read_rootfs_img_from_file
*/

static long file_len = 0;

// read component number from head of file
static int read_component_info(FILE *file_id, unsigned int component_type,
                        COMPONET_S *info) {

  char buf[MAX_HEAD_LEN] = {0};
  unsigned char component_num = -1;
  unsigned char i = 0;
  TOPIMAGEHEADER_S *top_image_head = NULL;
  int top_image_hd_len = sizeof(TOPIMAGEHEADER_S);

  fseek(file_id, 0L, SEEK_SET);
  if (!fread(buf, top_image_hd_len, 1, file_id)) {
    printf("    read top image head failed!\n");
    return -1;
  }
  top_image_head = (TOPIMAGEHEADER_S *)buf;
  component_num = top_image_head->component_num;
  printf("    got component number: %d\n", component_num);

  for (i = 0; i < component_num; i++) {
    if (top_image_head->component[i].component_type == component_type) {
      printf("    head component offset: %d\n",
             top_image_head->component[i].component_offset);
      memcpy(info, top_image_head->component + i, sizeof(*info));
      return 0;
    }
  }
  return -1;
}

// extract compressed image file from bin file according to offset and length
static int copy_file_content(FILE *file_id, const char *output_filename,
                             unsigned int image_offset,
                             unsigned int image_length) {
  if (!file_id) {
    return -1;
  }
  char read_buff[10240] = {0};
  int read_len_total = 0;
  int read_len_once = 0;
  int remain_len = 0;
  int rw_cnt;

  FILE *output_id = fopen(output_filename, "w+");
  if (!output_id) {
    printf("    Open output file %s failed.\n", output_filename);
    return -1;
  }
  fseek(file_id, 0L, SEEK_SET);
  while (read_len_total != image_length) {
    if (image_offset + read_len_total > file_len) {
      printf("    read will out of range: %d, %ld\n", read_len_total, file_len);
      return -1;
    }
    fseek(file_id, image_offset + read_len_total, SEEK_SET);

    remain_len = image_length - read_len_total;
    read_len_once = (10240 < remain_len) ? 10240 : remain_len;
    rw_cnt = fread(read_buff, 1, read_len_once, file_id);
    rw_cnt = fwrite(read_buff, 1, read_len_once, output_id);
    read_len_total += rw_cnt;
  }
  return 0;
}

// read offset and length of actually copmressed image file, and extract it
static int handel_rootfs_component(FILE *file_id, COMPONET_S *info,
                            const char *rootfs_img) {

  char buf[MAX_HEAD_LEN] = {0};
  unsigned short i = 0;
  SUBIMAGEHEADER_S *sub_image_header = NULL;
  int sub_image_head_len = sizeof(SUBIMAGEHEADER_S);
  unsigned int section_offset = 0;
  unsigned int image_offset = 0;
  unsigned int image_length = 0;

  fseek(file_id, info->component_offset, SEEK_SET);
  if (!fread(buf, sub_image_head_len, 1, file_id)) {
    printf("    read sub image head failed!\n");
    return -1;
  }
  sub_image_header = (SUBIMAGEHEADER_S *)buf;
  printf("    get section number: %d\n", sub_image_header->section_number);

  for (i = 0; i < sub_image_header->section_number; i++) {
    if (sub_image_header->section[i].section_type == SECTION_TYPE_FW) {
      section_offset = sub_image_header->section[i].section_offset;
      image_offset = info->component_offset + section_offset;
      image_length = sub_image_header->section[i].section_length;
      printf("    rootfs image offset: %d\t length: %d\n", image_offset,
             image_length);
      if (copy_file_content(file_id, rootfs_img, image_offset, image_length) !=
          0) {
        printf("    extract compressed image file failed\n");
        return -1;
      }
      return 0;
    }
  }
  return 0;
}

// read offset and length of actually copmressed image file, and extract it
static int handel_uboot_component(FILE *file_id, COMPONET_S *info,
                           const char *uboot_bin) {
  copy_file_content(file_id, uboot_bin, info->component_offset,
                    info->component_length);
  return 0;
}

int extractv6(const char *hpm_bin, const char *rootfs_img,
              const char *uboot_bin) {

  // variable definition
  unsigned int component_offset = 0;
  int ret = 0;

  // parse input

  // open file
  FILE *file_id = fopen(hpm_bin, "r+");
  if (!file_id) {
    printf("    Open file %s failed.\n", hpm_bin);
    return -1;
  }
  fseek(file_id, 0L, SEEK_END);
  file_len = ftell(file_id);
  fseek(file_id, 0L, SEEK_SET);
  printf("    file size: %ld\n", file_len);

  // start reading file
  COMPONET_S info = {0};
  printf("Start read %s\n", rootfs_img);
  ret = read_component_info(file_id, ROOTFS_HEAD_COMPONENT_TYPE, &info);
  if (ret != 0) {
    printf("    Read rootfs component info failed\n");
    return ret;
  }
  if (handel_rootfs_component(file_id, &info, rootfs_img) != 0) {
    printf("    Read rootfs image failed\n");
    return -1;
  }
  printf("Start read %s\n", uboot_bin);
  ret = read_component_info(file_id, M3_UBOOT_COMPONENT_TYPE, &info);
  if (ret != 0) {
    printf("    Read uboot component info failed\n");
    return ret;
  }
  if (handel_uboot_component(file_id, &info, uboot_bin) != 0) {
    printf("    Read uboot image failed\n");
    return -1;
  }

  return 0;
}

```
extractv6.h
```c
#define MAX_NAME_LENGTH    256
#define MAX_COMPONENT_NUM   31
#define MAX_HEAD_LEN 1024

#define M3_UBOOT_COMPONENT_TYPE       0
#define ROOTFS_HEAD_COMPONENT_TYPE    1
#define ROOTFS_IMG_COMPONENT_TYPE     2

#define INVAILD_SECTION_TYPE 0
#define SECTION_TYPE_FW      4

typedef struct
{
    unsigned int section_type;
    unsigned int section_offset;
    unsigned int section_length;
}SECTION_S;
 
typedef struct
{
    unsigned int preamble; //0x55aa55aa
    unsigned int file_len; // = Customer CRL Section Offset + Section Length;
    unsigned short firmware_type; // always be 3
    unsigned short section_number; // always be 7
    unsigned char reserved[64];
    SECTION_S section[7]; 
    unsigned int head_magic; //0x33cc33cc
}SUBIMAGEHEADER_S;

typedef struct
{
    unsigned int component_type;
    unsigned int component_offset;
    unsigned int component_length;
    unsigned int reserved;
}COMPONET_S;

typedef struct  // 512byte
{
    unsigned char component_num; 
    unsigned char reserved[15];
    COMPONET_S component[MAX_COMPONENT_NUM];
}TOPIMAGEHEADER_S;

int extractv6(const char *hpm_bin, const char *rootfs_img, const char *uboot_bin);

```
