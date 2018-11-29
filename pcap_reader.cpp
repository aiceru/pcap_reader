#include <iostream>
#include <cstdlib>

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>
#include <time.h>

using namespace std;

/*
 *  pcap file header
 *  +-------------------+------------+------------+------------------------+
 *  |         4         |      2     |      2     |            4           |
 *  +-------------------+------------+------------+------------------------+
 *  | MAGIC(0xA1B2C3D4) | Major. Ver | miner. Ver | gmt to localcorrection |
 *  +-------------------+------------+------------+------------------------+
 *  |         4         |            4            |            4           |
 *  +-------------------+-------------------------+------------------------+
 *  |   Captured time   |    max length of snap   |      datalink type     |
 *  +-------------------+-------------------------+------------------------+
 */

#define PCAP_DATALINK_TYPE_ETHERNET 1

typedef struct _pcap_fheader
{
#define MAGIC 0xa1b2c3d4
  int magic;
  unsigned short version_major;
  unsigned short version_minor;
  int thiszone;
  unsigned sigfigs;
  unsigned snaplen;
  unsigned linktype;
}pcap_fheader;

/*
 * pcap header
 * +------------------------------+-----------------+---------------+
 * |               8              |        4        |       4       |
 * +------------------------------+-----------------+---------------+
 * | seconds(4) | microseconds(4) | captured length | packet length |
 * +------------+-----------------+-----------------+---------------+
 */

typedef struct _pcap_header
{
  unsigned sec;
  unsigned usec;
  unsigned caplen;
  unsigned len;
}pcap_header;

/*
 * +---------+---------+-------+
 * |    6    |    6    |   2   |
 * +---------+---------+-------+
 * | DA(MAC) | SA(MAC) | EType |
 * +---------+---------+-------+
 */

typedef struct _eth_header
{
  unsigned char damac[6];
  unsigned char samac[6];
  unsigned short etype;
}eth_header;

typedef struct _ip_header
{
  uint8_t ver_ihl;
  uint8_t tos;
  unsigned short tot_len;
  unsigned short identification;
  unsigned short frag_ops;
  uint8_t ttl;
  uint8_t proto_id;
  uint16_t h_checksum;
  uint32_t saip;
  uint32_t daip;
}ip_header;

typedef struct _udp_header
{
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
}udp_header;

#define MAX_PACKET 10000
pcap_header headers[MAX_PACKET];
int pcnt;

int read_pcap_fheader(int fd, pcap_fheader *pfheader)
{
  int nread = read(fd, pfheader, sizeof(pcap_fheader));
  if(nread < 0) {
    cout << strerror(errno) << '\n';
    return -1;
  } else if (nread == 0) {
    cout << "FEOF\n";
    return 0;
  } else {
    //cout << "MAGIC : " << std::hex << pfheader->magic << std::dec << '\n';
    //cout << "Major version : " << pfheader->version_major << '\n';
    //cout << "minor version : " << pfheader->version_minor << '\n';
    //cout << "thiszone : " << pfheader->thiszone << '\n';
    //cout << "captured time : " << pfheader->sigfigs << '\n';
    //cout << "snap length : " << pfheader->snaplen << '\n';
    //cout << "link type : " << pfheader->linktype << '\n';
    return nread;
  }
}

int read_pcap_header(int fd, pcap_header *pheader)
{
  int nread = read(fd, pheader, sizeof(pcap_header));
  if(nread < 0) {
    cout << strerror(errno) << '\n';
    return -1;
  } else if (nread == 0) {
    cout << "FEOF\n";
    return 0;
  } else {
    //cout << "timestamp: " << pheader->sec << ":" << pheader->usec << '\n';
    //cout << "captured len: " << pheader->caplen << '\n';
    //cout << "packet len: " << pheader->len << '\n';
    if (pheader->caplen != pheader->len) {
      printf("captured len is diff from packet len!!\n");
    }
    return nread;
  }
}

int read_eth_header(int fd, eth_header *eheader)
{
  int nread = read(fd, eheader, sizeof(eth_header));
  eheader->etype = ntohs(eheader->etype);
  if(nread < 0) {
    cout << strerror(errno) << '\n';
    return -1;
  } else if (nread == 0) {
    cout << "FEOF\n";
    return 0;
  } else {
    //cout << "etype : " << std::hex << eheader->etype << '\n';
    return nread;
  }
}

int read_ip_header(int fd, ip_header *ih, int pkt_num)
{
  int nread = read(fd, ih, sizeof(ip_header));
  ih->tot_len = ntohs(ih->tot_len);
  if(nread < 0) {
    cout << strerror(errno) << '\n';
    return -1;
  } else if (nread == 0) {
    cout << "FEOF\n";
    return 0;
  } else {
    //cout << "IP version : " << ((ih->ver_ihl & 0xF0) >> 4) << '\n';
    //cout << "IP header len : " << (ih->ver_ihl & 0x0F) * 4<< '\n';
    if((ih->ver_ihl & 0x0F) * 4 != 20) {
      cout << "IP header length is not 20!!\n";
    }
    if(ih->proto_id != 17) {
      //cout << "Not UDP packet, " << ih->proto_id << '\n';
      //cout << pkt_num << "th pkt. " << '\n';
    }
    return nread;
  }
}

int read_udp_header(int fd, udp_header *uh, int pkt_num)
{
  int nread = read(fd, uh, sizeof(udp_header));
  uh->len = ntohs(uh->len);
  uh->dport = ntohs(uh->dport);
  if(nread < 0) {
    cout << strerror(errno) << '\n';
    return -1;
  } else if (nread == 0) {
    cout << "FEOF\n";
    return 0;
  } else {
    return nread;
  }
}

#define RECV_ADDR "127.0.0.1"
#define RECV_PORT 50000

int main(int argc, char *args[])
{
  if (argc < 6) {
    printf("Usage:\n");
    printf("pcap_reader [FILE NAME] [DST PORT of TARGET PKT] [PKT START] [PKT LIMIT] [LOOP LIMIT]\n");
    return 0;
  }

  int target_port = 0;
  char *filename;

  struct timespec elapsed_tv;
  struct timespec last_tv;
  struct timespec delay_tv;

  elapsed_tv.tv_sec = 0;
  elapsed_tv.tv_nsec = 0;
  last_tv.tv_sec = 0;
  last_tv.tv_nsec = 0;
  int time_diff;

  int pkt_elapsed = 0;

  filename = args[1];
  target_port = atoi(args[2]);

  int pkt_start = atoi(args[3]);
  int pkt_limit = atoi(args[4]);
  
  int loop_limit = atoi(args[5]);

  //int fd = open("pcap/BIGBUNNY(1sec).pcap", O_RDONLY);
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    cout << strerror(errno) << '\n';
    return -1;
  }

  uint32_t first_ip_saaddr = 0;

  int ret, nread;
  pcap_fheader pfh;

  pcap_header ph;
  eth_header eh;
  ip_header ih;
  udp_header uh;

  int mmtp_pkt_len = 0;
  char *mmtp_pkt_buf;

  int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
  if(sockfd < 0) {
    cout << strerror(errno) << '\n';
    return -1;
  }

  struct sockaddr_in recv_addr;
  memset(&recv_addr, 0, sizeof(recv_addr));
  recv_addr.sin_family = AF_INET;
  recv_addr.sin_port = htons(RECV_PORT);
  recv_addr.sin_addr.s_addr = inet_addr(RECV_ADDR);

  for(int i = 0; i < loop_limit; i++) {
    lseek(fd, 0, SEEK_SET);

    ret = read_pcap_fheader(fd, &pfh);
    if(ret < 0) {
      return ret;
    }

    if(pkt_limit == 0) {
      pkt_limit = INT_MAX;
    }

    elapsed_tv.tv_sec = 0;
    elapsed_tv.tv_nsec = 0;
    last_tv.tv_sec = 0;
    last_tv.tv_nsec = 0;
    delay_tv.tv_sec = 0;
    delay_tv.tv_nsec = 0;

    for(int j = 0; j < pkt_limit; j++) {
      ret = read_pcap_header(fd, &ph);
      if(ret < 0) {
        return ret;
      } else if(ret == 0) {
        break;
      }

      ret = read_eth_header(fd, &eh);
      if(ret < 0) {
        return ret;
      } else if(ret == 0) {
        break;
      }

      if(eh.etype == 0x0806) {    // ARP packet
        if(lseek(fd, ph.len - sizeof(eth_header), SEEK_CUR) < 0) {
          cout << strerror(errno) << '\n';
          return -1;
        }
        continue;
      }

      ret = read_ip_header(fd, &ih, j);
      if(ret < 0) {
        return ret;
      } else if(ret == 0) {
        break;
      }

/*
      if(first_ip_saaddr == 0) {
        first_ip_saaddr = ih.saip;
        printf("first_ip_saaddr = %ld\n", first_ip_saaddr);
      }

      if(ih.saip != first_ip_saaddr) {
        lseek(fd, ph.len - sizeof(ip_header), SEEK_CUR);
        continue;
      }
*/


      ret = read_udp_header(fd, &uh, j);
      if(ret < 0) {
        return ret;
      } else if(ret == 0) {
        break;
      }
      if(uh.dport != target_port) {
        lseek(fd, uh.len - sizeof(udp_header), SEEK_CUR);
        continue;
      }

      {
        elapsed_tv.tv_sec = (time_t)ph.sec - last_tv.tv_sec;
        elapsed_tv.tv_nsec = (long)(ph.usec*1000) - last_tv.tv_nsec;

        if(last_tv.tv_sec != 0 && last_tv.tv_nsec != 0 && j % 10 != 0) {
          nanosleep(&elapsed_tv, NULL);
        }

        mmtp_pkt_len = uh.len - sizeof(udp_header);
        //      cout << "MMTP packet length is : " << mmtp_pkt_len << '\n';

        mmtp_pkt_buf = (char *)malloc(mmtp_pkt_len);

        nread = read(fd, mmtp_pkt_buf, mmtp_pkt_len);
        if(nread < 0) {
          cout << strerror(errno) << '\n';
          return -1;
        } else if (nread == 0) {
          cout << "FEOF\n";
          break;
        }

        if (j < pkt_start) continue;
        printf("%d:%d %d bytes sent\n", i, j, sendto(sockfd, mmtp_pkt_buf, mmtp_pkt_len, 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr)));
        //sendto(sockfd, mmtp_pkt_buf, mmtp_pkt_len, 0, (struct sockaddr *)&recv_addr, sizeof(recv_addr));

        //gettimeofday(&last_tv, NULL);

        last_tv.tv_sec = ph.sec;
        last_tv.tv_nsec = (long)(ph.usec*1000);

        free(mmtp_pkt_buf);
      }
    }
  }
  close(sockfd);
}
