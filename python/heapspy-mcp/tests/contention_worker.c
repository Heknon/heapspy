// Copy of the workload from the CPU-contention blind test, used by
// tests/test_contention_live.py. Usage: worker WS_BYTES RATE STEPS STATSFILE.
// Request-driven worker: each request walks part of a private working set.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/prctl.h>
#include <unistd.h>
typedef struct node { uint32_t next; char pad[60]; } node;
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
int main(int argc,char**argv){
  if(argc<5){fprintf(stderr,"usage: worker WS_BYTES RATE STEPS STATSFILE\n");return 2;}
  size_t ws=strtoull(argv[1],0,10); double rate=atof(argv[2]); long steps=atol(argv[3]); const char*sf=argv[4];
  prctl(PR_SET_NAME,"svc-worker");
  size_t n=ws/sizeof(node); node*a=aligned_alloc(64,n*sizeof(node));
  uint32_t*perm=malloc(n*4); for(size_t i=0;i<n;i++)perm[i]=i;
  srand(getpid()); for(size_t i=n-1;i>0;i--){size_t j=rand()%(i+1);uint32_t t=perm[i];perm[i]=perm[j];perm[j]=t;}
  for(size_t i=0;i<n;i++)a[perm[i]].next=perm[(i+1)%n]; free(perm);
  uint32_t p=0; unsigned long done=0; double start=now(), due=start, last=start;
  for(;;){
    double t=now();
    if(due>t){ double d=due-t; struct timespec s={(time_t)d,(long)((d-(time_t)d)*1e9)}; nanosleep(&s,0); continue; }
    if(t-due>1.0) due=t-1.0;               /* cap backlog at 1 s */
    for(long k=0;k<steps;k++) p=a[p].next;  /* one request */
    done++; due+=1.0/rate;
    if(t-last>=0.5){ FILE*f=fopen(sf,"w"); if(f){fprintf(f,"%lu %.6f %u\n",done,t,p);fclose(f);} last=t; }
  }
}
