#define INQUIRY_CMDLEN  6
#define INQUIRY_CMD     0x12
#define SENSE_BUFF_LEN  32
#define DEF_TIMEOUT     60000
#define RECOVERED_ERROR 0x01
#define MX_ALLOC_LEN    255
#define WWID_SIZE       33
#define BLKGETSIZE      _IO(0x12,96)

/* exerpt from "sg_err.h" */
#define SCSI_CHECK_CONDITION    0x2
#define SCSI_COMMAND_TERMINATED 0x22
#define SG_ERR_DRIVER_SENSE     0x08

void basename (char *, char *);
int get_serial (char *, char *);
int get_lun_strings (char *, char *, char *, char *);
int get_evpd_wwid(char *, char *);
long get_disk_size (char *);
