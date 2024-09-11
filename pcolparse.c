#include "pcolparse.h"

//Purpose is to parse IP protocol packets, encapsulating details of
//their layout


IP_packet* parse_ip_packet(FILE** f, int offset){
    FILE* fp = *f;
    IP_packet* ret = (IP_packet*)malloc(sizeof(IP_packet));
    fseek(fp,offset,SEEK_SET);
    
    //Read version number and the IHL
      uint32_t r = 0;  
      if(fread(&r, sizeof(uint32_t), 1, fp) != 1){
        perror("Couldn't read from file\n");
        fclose(fp);
        free(ret);
        return NULL;
      }
      r = ntohl(r);
  
      //Version, IHL, Type of service, total length
      ret->version = (unsigned char) (r >> 28);
      ret->IHL = (unsigned char) ((r & 0x0F000000) >> 24);
      ret->type_of_service = (unsigned char) ((r & 0x00FF0000) >> 16);
      ret->total_length = (unsigned short) (r & 0x0000FFFF);
      
      //Move to source and destination address
      uint32_t addr[2] = {0,0};
      fseek(fp,(4 * (3)) + offset,SEEK_SET);
      if(fread(addr, sizeof(uint32_t), 2, fp) != 2){
        perror("Couldn't read from file\n");
        fclose(fp);
        free(ret);
        return NULL;
      }
      ret->source_address.s_addr =  addr[0];
      ret->destination_address.s_addr = addr[1];
      
        
      return ret;
  }


TCP_packet* parse_tcp_packet(FILE** f, int offset){
    FILE* fp = *f;
    TCP_packet* ret = (TCP_packet*)malloc(sizeof(IP_packet));
    fseek(fp,offset,SEEK_SET);
    
    //Read version number and the IHL
      unsigned short r[2] = {0,0};  
      if(fread(&r, sizeof(unsigned short), 2, fp) != 2){
        perror("Couldn't read from file\n");
        fclose(fp);
        free(ret);
        return NULL;
      }
      
      //Version, IHL, Type of service, total length
      ret->source_port = (unsigned short) (ntohs(r[0]));
      ret->dest_port = (unsigned short) (ntohs(r[1]));
      
      //Data offset
      fseek(fp, (4 * 3) + offset, SEEK_SET);
      uint32_t data_offset = 0; 
      if(fread(&data_offset, sizeof(uint32_t), 1, fp) != 1){
        perror("Couldn't read from file\n");
        fclose(fp);
        free(ret);
        return NULL;
      }

      ret->data_offset = (unsigned char) ((ntohl(data_offset) & 0xF0000000) >> 28);

      
      
      return ret;
  }

//Parse TCP and IP packet pair
pack_list* parse_tcp_ip_packets(FILE** fp, int offset){
  IP_packet* i = parse_ip_packet(fp, offset);
    if(i == NULL){
      return NULL;
    }
    TCP_packet* t = parse_tcp_packet(fp, i->IHL*4 + offset);
    if(t == NULL){
      return NULL;
    }
    pack_list* ret = (pack_list*)malloc(sizeof(pack_list));
    ret->ip = i;
    ret->tcp = t;
    if(i->total_length*4 > i->IHL + t->data_offset){
      int data_size = (i->total_length*4) - i->IHL - t->data_offset;
      ret->tcp->data = (char*) malloc(data_size);

      fseek(*fp, offset + 4*(ret->ip->IHL + ret->tcp->data_offset), SEEK_SET);
      int n = fread(ret->tcp->data, sizeof(char), (i->total_length*4) - i->IHL - t->data_offset, *fp);
      if(n < 0){
        perror("Error reading data from packet\n");
        free(ret->tcp->data);
        free(ret->tcp);
        free(ret->ip);
        free(ret);
        return NULL;
      }
    }else{
      ret->tcp->data = NULL;
    }
    return ret;
}

pack_list* parse_packets(FILE** fp){
    //Get size of file
    fseek(*fp, 0, SEEK_END);
    int size = ftell(*fp); 
    fseek(*fp, 0, SEEK_SET); 
    int offset = 0;

    pack_list* ret = NULL;
    pack_list** last = NULL;
    while(offset < size){
      pack_list* temp = parse_tcp_ip_packets(fp, offset);
      if(temp == NULL){ //Error occured
        free_pack_list(ret);
        perror("Error has occured");
        return NULL;
      }
      if(ret == NULL){
        ret = temp;
        last = &ret->next;
      }else{
        *last = temp;
        last = &temp->next;
      }
      offset += temp->ip->total_length;
    }

    
    
    return ret;
  }


void free_pack_list(pack_list* p){
  while(p != NULL){
    pack_list* temp = p;
    p = p->next;
    if(temp->tcp->data != NULL){
      free(temp->tcp->data);
    }
    free(temp->tcp);
    free(temp->ip);
    free(temp);
  }
}