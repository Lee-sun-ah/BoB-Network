#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <stdlib.h>

uint32_t fileopen(char argv[]){
	uint32_t a;
	
	FILE *fp=fopen(argv,"rb");
	
	size_t readlen=fread(&a,1,sizeof(uint32_t),fp);
	if (readlen != sizeof(uint32_t)){
		fprintf(stderr,"fread return %lu\n",readlen);
		exit(-1);
	}
	
	fclose(fp);
	
	return a;
}
int main(int argc, char *argv[]){
	uint32_t a,b,c;
	a=fileopen(argv[1]);
	b=fileopen(argv[2]);

	a=ntohl(a);
	b=ntohl(b);
	c=a+b; 
	printf("%d(%#x) + %d(%#x) = %d(%#x)\n",a,a,b,b,c,c);	

	return 0;

}
