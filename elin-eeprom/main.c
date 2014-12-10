/*------------------------------------------------------------------------------
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 u-blox AG, Sweden.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Component   : ELIN-W16 platform - EEPROM parser
 * File        : main.c
 *
 * Description : Utility to read and parse i2c EEPROM on ODIN-W16 and ELIN-W160
 *------------------------------------------------------------------------------*/

/*===========================================================================
 * INCLUDES
 *=========================================================================*/
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <time.h>
#include <assert.h>
#include <string.h>

/*===========================================================================
 * DEFINES
 *=========================================================================*/

/* Parameter Types */
#define TYPE_MAGIC		0xcbc184d4
#define TYPE_ODIN_W16_NVS	0x54c98a2c
#define TYPE_TIME		0x1e89248d
#define TYPE_RIG		0x98cb2e43
#define TYPE_ICID		0xb70388a4
#define TYPE_FCCID		0x96530317
#define TYPE_BTADDR		0xce4dcb07
#define TYPE_SERIAL		0x70bb1304
#define TYPE_RESERVED		0x3fa89423
#define TYPE_CUSTOM		0x6afcd241
#define NBR_RESERVED_PARAMS	9

/* Parameter type sizes */
#define ODIN_W16_NVS_FILE_SIZE	912
#define FCC_ID_SIZE		32
#define IC_ID_SIZE		32
#define SERIAL_SIZE		32
#define TIME_SIZE		8
#define RIG_ID_SIZE		8
#define BT_ADDR_SIZE		6
#define PARAM_TYPE_SIZE		8
#define RESERVED_SIZE	(RESERVED_AREA_SIZE - ODIN_W16_NVS_FILE_SIZE - \
			FCC_ID_SIZE - IC_ID_SIZE - SERIAL_SIZE - \
			TIME_SIZE - RIG_ID_SIZE - BT_ADDR_SIZE - \
			PARAM_TYPE_SIZE*NBR_RESERVED_PARAMS)
#define CUSTOM_SIZE	(EEPROM_SIZE - RESERVED_AREA_SIZE-PARAM_TYPE_SIZE) - 1

/* EEPROM settings */
#define EEPROM_SIZE		8192
#define EEPROM_MAX_READ_SIZE	4096
#define EEPROM_MAX_WRITE_SIZE	4096
#define RESERVED_AREA_SIZE	2048

#ifndef VERSION
	#define VERSION "0.1"
#endif

#define VERBOSE(...)    do { \
	if (verbose) printf(__VA_ARGS__); \
} while (0)

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
struct __attribute__((__packed__)) tlv_header {
	uint32_t type;
	uint32_t length;
} tlv_header;

struct __attribute__((__packed__)) tlv_data {
	struct tlv_header header;
	uint8_t value[];
} tlv_data;

/*===========================================================================
 * DEFINITIONS
 *=========================================================================*/
static struct tlv_header all_tlvs[] = {
	{ TYPE_MAGIC, 0 },
	{ TYPE_ODIN_W16_NVS, ODIN_W16_NVS_FILE_SIZE },
	{ TYPE_TIME, TIME_SIZE },
	{ TYPE_RIG, RIG_ID_SIZE },
	{ TYPE_ICID, IC_ID_SIZE },
	{ TYPE_FCCID, FCC_ID_SIZE },
	{ TYPE_BTADDR, BT_ADDR_SIZE },
	{ TYPE_SERIAL, SERIAL_SIZE },
	{ TYPE_RESERVED, RESERVED_SIZE},
	{ TYPE_CUSTOM, CUSTOM_SIZE},
};

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/

void init_eeprom_lock(void){
	int fd;
	fd = open("/sys/class/gpio/export",O_WRONLY);
	write(fd, "50", 2);
	close(fd);
	fd = open("/sys/class/gpio/gpio50/direction",O_WRONLY);
	write(fd, "out", 3);
	close(fd);
}

void release_eeprom_lock(void){
	int fd = open("/sys/class/gpio/gpio50/direction",O_WRONLY);
	write(fd, "in", 2);
	close(fd);
	fd = open("/sys/class/gpio/unexport",O_WRONLY);
	write(fd, "50", 2);
	close(fd);
}

void set_eeprom_lock(int lock){
	int fd = open("/sys/class/gpio/gpio50/value",O_WRONLY);
	if(lock)
		write(fd, "1", 1);
	else
		write(fd, "0", 1);
	close(fd);
}

inline void eeprom_unlock(void){
	set_eeprom_lock(0);
}

inline void eeprom_lock(void){
	set_eeprom_lock(1);
}

int read_bytes(int fd, unsigned int addr, void *buf, int length){
	int read_size=0,ret=0,tmp=0;
	while(length > 0){
		if(length <= EEPROM_MAX_READ_SIZE){
			read_size = length;
		}else{
			read_size = EEPROM_MAX_READ_SIZE;
		}
		lseek(fd, addr, SEEK_SET);
		tmp = read(fd, buf, read_size);
		if (tmp != read_size) {
			printf("Error reading data. Bytes read:%d\n",tmp);
			return 0;
		}
		length -= read_size;
		buf += read_size;
		ret += read_size;
		addr += read_size;
	}
	length = ret;
	return length;
}

int write_bytes(int fd, unsigned int addr, void *buf, int length)
{
	int write_size = 0,ret = 0,tmp = 0;

	if(addr < RESERVED_AREA_SIZE){
		printf("Cannot write into reserved area\n");
		return 0;
	}

	while(length > 0){
		if(length <= EEPROM_MAX_WRITE_SIZE){
			write_size = length;
		}else{
			write_size = EEPROM_MAX_WRITE_SIZE;
		}
		lseek(fd, addr, SEEK_SET);
		tmp = write(fd, buf, write_size);
		if(tmp != write_size){
			fprintf(stderr,"Error writing data at byte:%d\n",ret+tmp);
			return 0;
		}
		buf += write_size;
		length -= write_size;
		addr += write_size;
		ret += write_size;
	}
	return ret;
}

int file_to_eeprom(int eeprom, char *filename, unsigned int addr,int size){
	int fd, tmp;
	uint8_t *buf;

	fd = open(filename, O_RDONLY);
	if(fd < 0){
		fprintf(stderr,"failed to open file: %s\n",filename);
		return 0;
	}

	if(size <= 0){
		size = lseek(fd, 0L, SEEK_END);
		lseek(fd, 0L, SEEK_SET);
	}

	if(size > CUSTOM_SIZE){
		fprintf(stderr,"Max file size: %d\n",CUSTOM_SIZE);
		return 0;
	}

	buf = malloc(size);
	tmp = read_bytes(fd, 0, buf, size);
	if (tmp != size) {
		fprintf(stderr,"Failed to read source file: %s\n",filename);
		close(fd);
		return 0;
	}
	eeprom_unlock();
	tmp = write_bytes(eeprom, addr, buf, size);
	if (tmp != size){
		fprintf(stderr,"Failed to write to eeprom\n");
		close(fd);
		return 0;
	}
	eeprom_lock();
	close(fd);
	return 1;
}

int eeprom_to_file(int eeprom, char *filename, int addr, int size){
	uint8_t *tmp = malloc(size);
	int output_fd;
	if (read_bytes(eeprom, addr, tmp, size) != size) {
		fprintf(stderr,"Couldn't read eeprom\n");
		return 0;
	}
	if ((output_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
		fprintf(stderr,"Couldn't create output file %s\n",filename);
		return 0;
	}
	if (write(output_fd, tmp, size) < 0) {
		fprintf(stderr,"Couldn't write output file %s\n",filename);
		return 0;
	}
	free(tmp);
	close(output_fd);
	return 1;
}

int write_tlv(int fd, int addr, struct tlv_data tlv){
	uint8_t *zerobuf;
	struct tlv_header head = tlv.header;

	if (write_bytes(fd, addr, &tlv, sizeof(head)) != sizeof(head)) {
		fprintf(stderr, "Failed to write TLV: %08x\n", head.type);
		return 0;
	}
	addr += sizeof(head);

	if (head.length) {
		zerobuf = malloc(head.length);
		memset(zerobuf,0,head.length);
		if (!zerobuf) {
			fprintf(stderr, "Failed to allocate zerobuf\n");
			return 0;
		}

		if (write_bytes(fd, addr, zerobuf, head.length) != head.length) {
			fprintf(stderr, "Failed to clear TLV data: %08x\n", head.type);
			return 0;
		}
		free(zerobuf);
	}
	return 1;
}

int array_empty(uint8_t *arr, int size) {
	while( size-- > 0){
		if(arr[size]!=0)
			return 0;
	}
	return 1;
}

static void print_usage(void)
{
	fprintf(stderr, "Usage: elin-eeprom -d <device> [ -v ] [ -n filename ] [ -w  filename ]\n");
	fprintf(stderr, "                   [ -r filename ] [ -h ]\n\n");
	fprintf(stderr, "  -d       i2c-dev eeprom device (Mandatory)\n");
	fprintf(stderr, "  -h       Show usage\n");
	fprintf(stderr, "  -n       Read ODIN-W16 NVS from eeprom to filename\n");
	fprintf(stderr, "  -r       Read custom area to filename\n");
	fprintf(stderr, "  -w       Write file to custom area\n");
	fprintf(stderr, "  -v       Verbose\n");
}

int main(int argc, char *argv[])
{
	int opt = -1, fd, addr = 0, verbose = 0;
	char *dev = NULL, *nvs_file = NULL, *filename;
	int read_cust_file = 0, write_cust_file = 0;
	struct tlv_data tlv;
	struct tlv_header head;

	printf("ELIN EEPROM reader version: %s\n", VERSION);

	do {
		opt = getopt(argc, argv, "d:vn:hn:ih:r:w:n:t");
		switch (opt) {
			case 'd':
				dev = optarg;
				break;
			case 'v':
				verbose = 1;
				break;
			case 'n':
				nvs_file = optarg;
				break;
			case 'r':
				read_cust_file = 1;
				filename = optarg;
				break;
			case 'w':
				write_cust_file = 1;
				filename = optarg;
				break;
			case 'h':
				print_usage();
				exit(1);
				break;
			default:
				break;
		}

	} while (opt != -1);

	if (read_cust_file != 0 && write_cust_file != 0) {
		fprintf(stderr, "Cannot read and write custom area simultaensosly\n");
		exit(1);
	}

	if (!dev) {
		fprintf(stderr, "No eeprom device set\n");
		exit(1);
	}

	if ((fd = open(dev, O_RDWR)) < 0) {
		perror("Can't open device i2c device");
		exit(1);
	}

	init_eeprom_lock();

	/* Identify EEPROM by finding magic tag */
	if (read_bytes(fd, 0, &tlv, sizeof(tlv_header)) != sizeof(tlv_header)) {
		fprintf(stderr, "Failed to read EEPROM magic byte\n");
		exit(1);
	}

	if (tlv.header.type != TYPE_MAGIC || tlv.header.length != 0) {
		fprintf(stderr, "No magic word found in EEPROM. EEPROM not initialized?\n");
		exit(1);
	}

	/* Iterate memory until hitting all ones */
	while (addr < (EEPROM_SIZE -1 )) {

		if (read_bytes(fd, addr, &tlv, sizeof(tlv_header)) != sizeof(tlv_header)) {
			exit(1);
		}
		head = tlv.header;

		if (head.type == 0xffffffff && head.length == 0xffffffff) {
			break;
		}

		addr += sizeof(tlv_header);

		if (addr+head.length > EEPROM_SIZE) {
			fprintf(stderr, "EEPROM content currupt at the end\n");
			break;
		}

		switch (head.type) {
			case TYPE_MAGIC:
				VERBOSE("Magic byte found. Parsing content\n");
				break;
			case TYPE_ODIN_W16_NVS:
				{
					uint8_t nvs[ODIN_W16_NVS_FILE_SIZE];
					int ret;
					assert(head.length == ODIN_W16_NVS_FILE_SIZE);
					ret = read_bytes(fd, addr, &nvs, head.length);
					if (ret != head.length) {
						VERBOSE("Failed to read EEPROM %d, %d\n",head.length,ret);
						exit(1);
					}
					if(!array_empty(nvs,head.length))
						VERBOSE("ODIN-W16 NVS present in EEPROM\n");
					if (nvs_file) {
						eeprom_to_file(fd,nvs_file,addr,ODIN_W16_NVS_FILE_SIZE);
					}
				}
				break;
			case TYPE_TIME:
				{
					unsigned long long temp;
					time_t time;

					assert(sizeof(temp) == head.length);

					if (read_bytes(fd, addr, &temp, head.length) != head.length) {
						exit(1);
					}
					time = (time_t)temp;
					if(temp)
						VERBOSE("Production timestamp: %s", ctime(&time));
				}
				break;
			case TYPE_RIG:
				{
					unsigned long long rig;

					assert(sizeof(rig) == head.length);

					if (read_bytes(fd, addr, &rig, head.length) != head.length) {
						exit(1);
					}
					if(rig)
						VERBOSE("Production rig ID: %llu\n", rig);
				}
				break;
			case TYPE_ICID:
				{
					uint8_t ic[IC_ID_SIZE + 1];

					memset(ic, 0, sizeof(ic));
					assert(head.length == IC_ID_SIZE);

					if (read_bytes(fd, addr, ic, head.length) != head.length) {
						exit(1);
					}
					if(!array_empty(ic,sizeof(ic)))
						VERBOSE("IC ID: %s\n", ic);
				}
				break;
			case TYPE_FCCID:
				{
					uint8_t fcc[FCC_ID_SIZE + 1];

					memset(fcc, 0, sizeof(fcc));
					assert(head.length == FCC_ID_SIZE);

					if (read_bytes(fd, addr, fcc, head.length) != head.length) {
						exit(1);
					}
					if(!array_empty(fcc,sizeof(fcc)))
						VERBOSE("FCC ID: %s\n", fcc);
				}
				break;
			case TYPE_BTADDR:
				{
					uint8_t bt[BT_ADDR_SIZE];

					assert(sizeof(bt) == head.length);

					if (read_bytes(fd, addr, bt, head.length) != head.length) {
						exit(1);
					}
					if(!array_empty(bt,sizeof(bt)))
						VERBOSE("Bluetooth address: %02x%02x%02x%02x%02x%02x\n",
							bt[0],bt[1],bt[2],bt[3],bt[4],bt[5]);
				}
				break;
			case TYPE_SERIAL:
				{
					uint8_t serial[SERIAL_SIZE + 1];

					memset(serial, 0, sizeof(serial));
					assert(head.length == SERIAL_SIZE);

					if (read_bytes(fd, addr, serial, head.length) != head.length) {
						exit(1);
					}
					if(!array_empty(serial,sizeof(serial)))
						VERBOSE("Serial number: %s\n", serial);
				}
				break;
			case TYPE_RESERVED:
				break;
			case TYPE_CUSTOM:
				{
					if (read_cust_file){
						eeprom_to_file(fd,filename,addr,CUSTOM_SIZE);
					}else if (write_cust_file){
						file_to_eeprom(fd,filename,addr,0);
					}else{
						VERBOSE("Custom area present\n");
					}
				}
				break;
			default:
				VERBOSE("Unknown TLV type 0x%08x (length %u)\n", head.type, head.length);
				break;
		}
		addr += head.length;
	}
	close(fd);
	release_eeprom_lock();
	return 0;
}

