# h3 Time

For this challenge, we are given the source code for the challenge. Let's take a look at it:

```
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
```

Looking at the main function, it appears to print out some ext, then prompt us for some input. This is after it generates a supposidly random number using C's `srand` function using time as a seed. Then it compares our input against the generated number, and if they are the same then it runs the `giveFlag` function which will print out the contents of the flag file. 

So in order to solve this challenge, we will need to know what number the `srand` function will output. Luckily for us, we know the seed which is the output of the `time` function. If we know the seed for the `srand` function, then we can generate the same sequence of numbers (so the sequence of numbers isn't actually random). So we should be able to write a C program which generates a number using the `srand` function with time as a seed, and pipe that into the challenge as our input, and that should solve the challenge.

Here is the code for the C program which will solve this challenge (may have gotten lazy and copy and pasted from the challenge's source code):

```
#include<stdio.h>
#include<time.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>

int main()
{
    uint32_t rand_num;
    srand(time(0)); //seed with current time
    rand_num = rand();
    uint32_t ans;
    printf("%d\n", rand_num);	
}
```

and when we try our solution:

```
./solve | ./time 
Welcome to the number guessing game!
I'm thinking of a number. Can you guess it?
Guess right and you get a flag!
Enter your number: Your guess was 1111322383.
Looking for 1111322383.
You won. Guess was right! Here's your flag:
flag{g0ttem_boyz}


```

The real flag was not `flag{g0ttem_boyz}`, that was just what I had in `/home/h3/flag.txt` to test my solution locally, prior to launching it against the server running the challenge.

Just like that, we captured the flag!
