/*---------------------------------------------------------------------------
 * Copyright (c) 2014 connectBlue AB, Sweden.
 * Any reproduction without written permission is prohibited by law.
 *
 * Component   : WGP platform - OWL355 EEPROM parser
 * File        : main.c
 *
 * Description : Utility to read and parse OWL355 i2c EEPROM on WGP cB-0960
 *-------------------------------------------------------------------------*/

/*===========================================================================
 * INCLUDES
 *=========================================================================*/
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>
#include <time.h>
#include <assert.h>

/*===========================================================================
 * DEFINES
 *=========================================================================*/
#define TYPE_MAGIC      0xcbc184d4
#define TYPE_NVS        0x54c98a2c
#define TYPE_TIME       0x1e89248d
#define TYPE_RIG        0x98cb2e43
#define TYPE_ICID       0xb70388a4
#define TYPE_FCCID      0x96530317
#define TYPE_BTADDR     0xce4dcb07
#define TYPE_SERIAL     0x70bb1304

#define EEPROM_SIZE     8192
#define ADDRESS_MASK    (EEPROM_SIZE - 1)

#define NVS_FILE_SIZE   912

#define VERBOSE(...)    do { \
                            if (verbose) printf(__VA_ARGS__); \
                        } while (0)

/*===========================================================================
 * DECLARATIONS
 *=========================================================================*/
struct tlv_header {
    unsigned int type;
    unsigned int length;
    unsigned char value[];
};

/*===========================================================================
 * FUNCTIONS
 *=========================================================================*/
static int read_bytes(int fd, unsigned int addr, void *buf, int length)
{
    lseek(fd, addr, SEEK_SET);
    if (read(fd, buf, length) != length) {
        perror("Error reading data");
        return -1;
    }

    return length;
}

static void print_usage(void)
{
    fprintf(stderr, "Usage: owl355_eeprom -d <device> [-v] [-n <filename>] [-h]]]\n\n");
    fprintf(stderr, "  -d       i2c-dev eeprom device (Mandatory)\n");
    fprintf(stderr, "  -v       Verbose\n");
    fprintf(stderr, "  -n       Write NVS to filename\n");
    fprintf(stderr, "  -h       Show usage\n");
}

int main(int argc, char *argv[])
{
    int opt = -1, fd, addr = 0, verbose = 0;
    char *dev = NULL, *nvs_file = NULL;
    struct tlv_header tlv;

    do {
        opt = getopt(argc, argv, "d:vn:h");
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
            case 'h':
                print_usage();
                exit(1);
                break;
            default:
                break;
        }

    } while (opt != -1);

    if (!dev) {
        fprintf(stderr, "No eeprom device set\n");
        exit(1);
    }

    if ((fd = open(dev, O_RDWR)) < 0) {
        perror("Can't open device i2c device");
        exit(1);
    }

    /* Identify EEPROM by finding cB magic tag */
    if (read_bytes(fd, 0, &tlv, sizeof(tlv)) != sizeof(tlv)) {
        exit(1);
    }

    if (tlv.type != TYPE_MAGIC || tlv.length != 0) {
        fprintf(stderr, "No magic found: type=0x%08x, length=%u\n", tlv.type, tlv.length);
        exit(1);
    }

    /* Iterate memory until hitting all ones */
    while (1) {
        if (read_bytes(fd, addr, &tlv, sizeof(tlv)) != sizeof(tlv)) {
            exit(1);
        }

        if (tlv.type == 0xffffffff && tlv.length == 0xffffffff) {
            break;
        }

        addr += sizeof(tlv);

        switch (tlv.type) {
            case TYPE_MAGIC:
                VERBOSE("TLV magic type: found\n");
                break;
            case TYPE_NVS:
                {
                    unsigned char nvs[NVS_FILE_SIZE];

                    assert(tlv.length == NVS_FILE_SIZE);

                    VERBOSE("NVS file: %u bytes\n", tlv.length);

                    if (read_bytes(fd, addr, nvs, tlv.length) != tlv.length) {
                        exit(1);
                    }

                    if (nvs_file) {
                        int nvs_fd;

                        if ((nvs_fd = open(nvs_file, O_WRONLY | O_CREAT | O_TRUNC,
                                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {
                            perror("Couldn't create NVS output file");
                            exit(1);
                        }

                        if (write(nvs_fd, nvs, NVS_FILE_SIZE) < 0) {
                            perror("Couldn't write NVS output file");
                            exit(1);
                        }

                        close(nvs_fd);

                    }

                    VERBOSE("WLAN address: %02X%02X%02X%02X%02X%02X\n",
                            nvs[11], nvs[10], nvs[6],
                            nvs[5], nvs[4], nvs[3]);
                }
                break;
            case TYPE_TIME:
                { 
                    unsigned long long temp;
                    time_t time;

                    assert(sizeof(temp) == tlv.length);


                    if (read_bytes(fd, addr, &temp, tlv.length) != tlv.length) {
                        exit(1);
                    }
                    time = (time_t)temp;

                    VERBOSE("Time: %s", ctime(&time));
                    VERBOSE("Time (raw): %llu\n", temp);
                }
                break;
            case TYPE_RIG:
                {
                    unsigned long long id;

                    assert(sizeof(id) == tlv.length);

                    if (read_bytes(fd, addr, &id, tlv.length) != tlv.length) {
                        exit(1);
                    }

                    VERBOSE("Rig ID: %llu\n", id);
                }
                break;
            case TYPE_ICID:
                VERBOSE("TLV ICID\n");
                break;
            case TYPE_FCCID:
                VERBOSE("TLV FCCID\n");
                break;
            case TYPE_BTADDR:
                VERBOSE("TLV BTADDR\n");
                break;
            case TYPE_SERIAL:
                VERBOSE("TLV SERIAL\n");
                break;
            default:
                VERBOSE("Unknown TLV type 0x%08x (length %u)\n", tlv.type, tlv.length);
                break;
        }

        if (tlv.length > EEPROM_SIZE) {
            fprintf(stderr, "EEPROM content currupt at the end\n");
            break;
        }

        addr += tlv.length;
    }

    close(fd);

    return 0;
}

