#include "pcolparse.h"
int main(int argc, char* argv[]){
    FILE *fp;

    if (argc != 2) {
        puts("Usage: summary <file>");
        return 1;
    }

    if ((fp=fopen(argv[1],"rb")) == 0) {
        printf("%s\n",argv[1]);
        perror("Cannot find file to serve. (23/24)");
        return 1;
   }

    pack_list* p = parse_packets(&fp);
   
    //Print the required data

    //First count packets
    int num = 0;
    pack_list* temp = p;
    while(temp != NULL){
        num +=1;
        temp = temp->next;
    }

    if(num > 0){
        printf("%s ", inet_ntoa(p->ip->source_address));
        printf("%s %d %d %d %d\n",
        inet_ntoa(p->ip->destination_address), p->ip->IHL, p->ip->total_length, p->tcp->data_offset, num);
    }else{
        printf("No packets\n");
    }
    free_pack_list(p);
    fclose(fp);
    return 0;
}