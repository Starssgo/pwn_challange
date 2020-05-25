#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <sys/prctl.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <fcntl.h>
//gcc domo.c -o domo -pie -lseccomp -z now -fPIC -s

#define key 9

extern void (*__free_hook) (void *__ptr,const void *);
extern void (*__malloc_hook) (void *__ptr,const void *);

char *str[key];
int num;
void initt()
	{
		num=0;	
		setvbuf(stdin, 0LL, 1, 0LL);
		setvbuf(stdout, 0LL, 2, 0LL);
		return setvbuf(stderr, 0LL, 1, 0LL);
	}
int Testing()
	{	
		if(__malloc_hook!=0 |__free_hook!=0)
			{
				puts("oh no");
				return 0;
			}
		return 1;
	}
void menu()
	{
		puts("1: Add a user");
		puts("2: Delete a user");
		puts("3: Show a user");
		puts("4: Edit a user");
		puts("5: Exit");
	}
void logo()
	{
		puts("                   .......                ");
		puts("                 .........:.:.:.          ");
		puts("                .........:::......         ");
		puts("               .......::::::::.....");
		puts("               :......:::::::::....");
		puts("              .-....::::::::::::....");
		puts("           .....-..:::::::::::::.....         ");
		puts("           :..:..:.::::::::::::......");
		puts("           ::.::::::::::::::::::...=:          ");
		puts("          .:..:::::::::::::::::.:=:.");
		puts("         ...:::::::::::::::::::-:               ");
		puts("        ...::::::::::::::::::=:");
		puts("        :..::::::::::::::::::                    ");
		puts("        ...::::::::::::::::-.                    ");
		puts("       .:..::::::::::::::::.                     ");
		puts("       ....::::::::::::::::.");
		puts("       ....::::::::::::::::.                      ");
		puts("       ....::::::::::::::::.                      ");
		puts("        ...:::::::::::-=-::.                      ");
		puts("        ...:::::::::--:.:=:.                      ");
		puts("        -..:.::::::::     .-:                     ");
		puts("        -....::::::-      .::                     ");
		puts("        :=..:::::::.       . :.                  ");
		puts("         .:..:::::-         :..                  ");
		puts("          -.....::.          ::                  ");
		puts("          :......:           :-.                 ");
		puts("           =.....:           .::                 ");
		puts("            =-...-            :::               ");
		puts("             :=...            .::               ");
		puts("              .-:             .::.             ");
		puts("                               ::.            ");
		puts("                               -.:            ");
		puts("                               ...           ");
		puts("                                 .           ");
		puts("                                ::.         ");
		puts("                                ::.        ");
		puts("                               .==.       ");
		puts("                                ..       ");
	}
void add()
	{
		if(Testing()==1)
			{
				if(num<key)
				{
					for(int i=0;i<key;i++)
						{
							if(str[i]==0)
								{
									int nbytes;
									puts("size:");
									scanf("%d", &nbytes);
									if(nbytes<0||nbytes>0x120)
										{
											puts("sobig");
											return ;
										}
									str[i]=malloc(nbytes);
									puts("content:");
									read(0,str[i],nbytes);
									str[i][nbytes]=0;
									num++;
									return ;
								}

						}

				}
			}
	}
void Delete()
	{
		if(Testing()==1)
			{
				int nbytes;
				puts("index:");
				scanf("%d", &nbytes);
				if(nbytes<0||nbytes>=key)
					{
						puts("NoNoNo");
						return ;
					}
				if ( str[nbytes] )
					{
						free(str[nbytes]);
						str[nbytes]=0;
						num--;
						puts("done");
					}
				else
					puts("no note");
			}

	}
void Show()
	{
		int nbytes;
		puts("index:");
		scanf("%d", &nbytes);
		if(nbytes<0||nbytes>=key)
			{
				puts("NoNoNo");
				return ;
			}
		if ( str[nbytes] )
			puts(str[nbytes]);
		else
			puts("no note");
	}
void Edit(int *flag1,int *flag2,int *flag3)
	{
		long int shell=0;
		if(Testing()==1)
			{
				if(*flag1&&*flag2&&*flag3)
					{
						puts("addr:");
						scanf("%ld",&shell);
						puts("num:");
						read(0,shell,1);
						*flag1=0;
						*flag2=0;
						*flag3=0;
						puts("starssgo need ten girl friend ");
					}
			
				else
					puts("You no flag");
			}
	}
int main()
{
	int flag1=1;
	int flag2=1;
	int flag3=1;
	int v1;
	initt();
	logo();
	printf("Welcome to GKCTF\n");
	while(1)
		{	
			menu();
			printf("> ");
			scanf("%d",&v1);
			if ( v1 == 1 )
			{
				add();
			}
			else if ( v1 == 2 )
			{
				Delete();
			}
			else if ( v1 == 3 )
			{
				Show();
			}
			else if ( v1 == 4 )
			{
				Edit(&flag1,&flag2,&flag3);
			}
			else
				break;
		}

	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_ALLOW);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sigreturn), 0);
	seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mprotect), 0);
	seccomp_load(ctx);
	printf("oh,Bye\n");

	return 0;

}
