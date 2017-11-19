#include<stdio.h>
#include<time.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

void giveFlag(void) {
    char flag[256];
    memset(flag, 0, 256);
    FILE* flag_handle = fopen("/home/h3/flag.txt", "r");
    if (flag_handle == NULL) {
        printf("Flag file not found!  Contact an H3 admin for assistance.\n");
        return;
    }
    fgets(flag, 256, flag_handle);
    fclose(flag_handle);
    printf("%s\n", flag);
}

int main(int argc, char **argv) {
    uint32_t rand_num;
    srand(time(0)); //seed with current time
    rand_num = rand();
    uint32_t ans;
    printf("Welcome to the number guessing game!\n");
    printf("I'm thinking of a number. Can you guess it?\n");
    printf("Guess right and you get a flag!\n");

    printf("Enter your number: ");
    fflush(stdout);
    scanf("%u", &ans); // get input from user
    printf("Your guess was %u.\n", ans);
    printf("Looking for %u.\n", rand_num);
    fflush(stdout);

    if (rand_num == ans) {
        printf("You won. Guess was right! Here's your flag:\n");
        giveFlag();
    } else {
        printf("Sorry. Try again, wrong guess!\n");
    }
    fflush(stdout);

    return 0;
}
