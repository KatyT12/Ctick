#include "pcolparse.h"

int main(int argc, char* argv[]){
    if (argc != 3) {
        puts("Usage: extract <input file> <output file>");
        return 1;
    }

    FILE* fp;
    
    if ((fp=fopen(argv[1],"rb")) == 0) {
        printf("%s\n",argv[1]);
        perror("Cannot find file to serve. (23/24)");
        return 1;
    }
    FILE* fw = fopen(argv[2],"wb");

    pack_list* p = parse_packets(&fp);
    while(p != NULL){
        if(p->tcp->data != NULL){
            //Write data
            int num_bytes = p->ip->total_length - 4*(p->ip->IHL + p->tcp->data_offset);
            int written = 0;
            while(written < num_bytes){
                written += fwrite(p->tcp->data, sizeof(char), num_bytes, fw);
            }
        }
        p = p->next;
    }

    return 0;
}