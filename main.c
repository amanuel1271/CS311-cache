#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define BYTES_PER_WORD 4
#define DUMP_CACHE_LEN  5
#define INFO_SIZE  4096
#define SEMI_COLON ":"
#define SPACE " "
#define MAX_LINE_LEN 1000
#define READ "R"
#define MAX_32 0xFFFFFFFF
#define CACHE_MISS -1

#define MASK_BLOCK_OFFSET(addr,block_bits) addr & (MAX_32 << block_bits)
#define EXTRACT_INDEX(addr,index_bits,block_bits)  (addr & ~(MAX_32 << (index_bits + block_bits))) >> block_bits
#define EXTRACT_TAG(addr,index_bits,block_bits) addr >> (index_bits + block_bits)

int total_read = 0,total_write = 0,write_back = 0;
int read_hit = 0,write_hit = 0,read_miss = 0,write_miss = 0;

struct cache_entry
{
	uint32_t data;
	uint32_t tag;
	uint8_t dirty_bit;
	uint8_t valid_bit;

};

typedef struct cache_block
{
	uint32_t set;
	uint32_t assoc;
	uint32_t capacity;
	uint32_t block_size;
	struct cache_entry **cache;


}CACHE;

typedef struct lrutable
{
	int isfullyoccupied;
	uint32_t *lruarr;

}LRU_TABLE;


void cdump(int capacity, int assoc, int blocksize){

	printf("Cache Configuration:\n");
        printf("-------------------------------------\n");
	printf("Capacity: %dB\n", capacity);
	printf("Associativity: %dway\n", assoc);
	printf("Block Size: %dB\n", blocksize);
	printf("\n");
}


void sdump(int total_reads, int total_writes, int write_backs,
	int reads_hits, int write_hits, int reads_misses, int write_misses) {
	printf("Cache Stat:\n");
        printf("-------------------------------------\n");
	printf("Total reads: %d\n", total_reads);
	printf("Total writes: %d\n", total_writes);
	printf("Write-backs: %d\n", write_backs);
	printf("Read hits: %d\n", reads_hits);
	printf("Write hits: %d\n", write_hits);
	printf("Read misses: %d\n", reads_misses);
	printf("Write misses: %d\n", write_misses);
	printf("\n");
}


void xdump(int set, int way, struct cache_entry ** cache)
{
	int i,j,k = 0;

	printf("Cache Content:\n");
        printf("-------------------------------------\n");
	
	for(i = 0; i < way;i++)
	{
		if(i == 0)
			printf("    ");
		
		printf("      WAY[%d]",i);
	}
	printf("\n");

	for(i = 0 ; i < set;i++)
	{
		printf("SET[%d]:   ",i);
		for(j = 0; j < way;j++)
			printf("0x%08x  ", cache[i][j].data);
		
		printf("\n");
	}
	printf("\n");
}




void Parse_Info(char *buf,uint32_t *capac,uint32_t *assoc,uint32_t *block_s)
{
	*capac = atoi(strtok(buf,SEMI_COLON));
	*assoc = atoi(strtok(NULL,SEMI_COLON));
	*block_s = atoi(strtok(NULL,SEMI_COLON));
}



void Init_Cache_Entries(CACHE  *d_cache)
{
	uint32_t set = d_cache->set;
	d_cache->cache = calloc(set,sizeof(struct cache_entry *));

	for (int i = 0; i < set; i++)
		d_cache->cache[i] = calloc(d_cache->assoc,sizeof(struct cache_entry));
}



LRU_TABLE *Init_LRU_table(uint32_t set,uint32_t assoc)
{
	LRU_TABLE *table = calloc(set,sizeof(LRU_TABLE));

	for (int i = 0; i < set; i++)
	{
		table[i].lruarr = calloc(assoc,sizeof(uint32_t));

		for (int j = 0; j < assoc; j++)
			table[i].lruarr[j] = assoc - j - 1;
	}
	return table;
}



int my_log_to_base_2(uint32_t num) // num must be power of two
{
	int count = 0;
	while (!(num & 0x1))
	{
		count++;
		num >>= 1;
	}
	return count;

}




int cache_hit(CACHE *dcache, uint32_t tag,uint32_t index)
{
	uint32_t assoc = dcache->assoc;

	for (int i = 0; i < assoc ; i++)
	{
		if (dcache->cache[index][i].valid_bit && (tag == dcache->cache[index][i].tag) )
			return i;
	}

	return CACHE_MISS;
}




uint32_t hex_string_to_int(char* hex_str)
{
    int num = (int)strtol(hex_str,NULL,16);
    return num;
}




void update_LRU_table(LRU_TABLE *table, int assoc_index, int cache_index,uint32_t assoc)
{
	uint32_t *entry = table[cache_index].lruarr,i = 0;

	if (assoc_index == entry[assoc - 1]) //  already most recently used, so dont do anything
		return;

	while (entry[i] != assoc_index)  i++;

	for (int j = i+1 ; j <= assoc - 1; j++)
		entry[j - 1] = entry[j];

	entry[assoc - 1] = assoc_index;
}




void handle_miss(LRU_TABLE *table,CACHE *dcache,int isfull,uint32_t data, uint32_t tag, uint32_t cache_index,int flag)
{
	if (isfull)
	{
		uint32_t evicted_block_index = table[cache_index].lruarr[0]; //LRU block

		if (dcache->cache[cache_index][evicted_block_index].dirty_bit)
			write_back++;

		dcache->cache[cache_index][evicted_block_index].data = data;
		dcache->cache[cache_index][evicted_block_index].tag = tag;
		dcache->cache[cache_index][evicted_block_index].dirty_bit = flag;
		update_LRU_table(table,evicted_block_index,cache_index,dcache->assoc);
	}
	else
	{
		int j = 0;

		for (; j < dcache->assoc ; j++)
			if (!dcache->cache[cache_index][j].valid_bit)
				break;

		dcache->cache[cache_index][j].valid_bit = 1;
		dcache->cache[cache_index][j].data = data;
		dcache->cache[cache_index][j].tag = tag;
		dcache->cache[cache_index][j].dirty_bit = flag;
		update_LRU_table(table,j,cache_index,dcache->assoc);

		if (j == dcache->assoc - 1)
			table[cache_index].isfullyoccupied = 1;
	}

}




void handle_cache(char *buf, CACHE *dcache,LRU_TABLE *table)
{
	char *action = strtok(buf,SPACE);
	uint32_t addr = hex_string_to_int(strtok(NULL,SPACE));

	uint32_t index_bits = my_log_to_base_2(dcache->set),block_bits = my_log_to_base_2(dcache->block_size);

	uint32_t data = MASK_BLOCK_OFFSET(addr,block_bits);
	uint32_t tag = EXTRACT_TAG(addr,index_bits,block_bits);
	uint32_t cache_index = EXTRACT_INDEX(addr,index_bits,block_bits);

	if (!strcmp(action,READ))
	{
		int cache_hit_status = cache_hit(dcache,tag,cache_index);

		if (cache_hit_status != CACHE_MISS) //cache hit
		{
			read_hit++;
			update_LRU_table(table,cache_hit_status,cache_index,dcache->assoc);

		}

		else // cache miss
		{
			//which block to evict
			int isfull = table[cache_index].isfullyoccupied;
			handle_miss(table,dcache,isfull,data,tag,cache_index,0);
			read_miss++;
		}

		total_read++;
	}
	else
	{
		//write hit and dirty bit
		int cache_hit_status = cache_hit(dcache,tag,cache_index);
		if (cache_hit_status != CACHE_MISS) //write hit
		{
			write_hit++;
			dcache->cache[cache_index][cache_hit_status].dirty_bit = 1;
			update_LRU_table(table,cache_hit_status,cache_index,dcache->assoc);

		}
		else
		{
			int isfull = table[cache_index].isfullyoccupied;
			handle_miss(table,dcache,isfull,data,tag,cache_index,1);
			write_miss++;

		}

		total_write++;
	}
}




int main(int argc, char *argv[]) { 

	char *filepath,*buf;
	int dump_cache_stat = false;

	if (argc ==  DUMP_CACHE_LEN)
	{
		dump_cache_stat = true;  
		filepath = argv[4];
	
	}

	else if (argc == DUMP_CACHE_LEN)
		filepath = argv[3];
	else
	{
		fprintf(stderr,"The number of command line arguments provided is not correct\n");
		return 1;
	}

	FILE *fp = fopen(filepath,"r");

	if (fp == NULL)
	{
		fprintf(stderr,"Error opening the file\n");
		return -1;
	}
	
	char *info_buf = calloc(INFO_SIZE,sizeof(char));
	buf = calloc(MAX_LINE_LEN,sizeof(char));

	CACHE data_cache;

	strcpy(info_buf,argv[2]);
	Parse_Info(info_buf,&data_cache.capacity,&data_cache.assoc,&data_cache.block_size);

	data_cache.set = data_cache.capacity/(data_cache.block_size * data_cache.assoc);
	
	Init_Cache_Entries(&data_cache);
	LRU_TABLE *table = Init_LRU_table(data_cache.set,data_cache.assoc);

	while (fgets(buf,MAX_LINE_LEN - 1, fp) != NULL)
	{
		handle_cache(buf,&data_cache,table);
		memset(buf,0,MAX_LINE_LEN * sizeof(char));
	}

	cdump(data_cache.capacity,data_cache.assoc,data_cache.block_size);
	sdump(total_read,total_write,write_back,read_hit,write_hit,read_miss,write_miss);

	if (dump_cache_stat)
		xdump(data_cache.set,data_cache.assoc,data_cache.cache);
	fclose(fp);

    return 0;
}
